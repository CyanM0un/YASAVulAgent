from __future__ import annotations

import asyncio
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from langchain_core.tools import StructuredTool

from .artifacts import ToolResultStore
from .budget import BudgetStop, TaskBudget
from .context import ContextManager
from .retry import RetryPolicy
from .tokens import TokenCounter
from .tools import parse_arguments, render_result


_PARALLEL_TOOL_NAMES = frozenset(
    {
        "list_directory",
        "glob",
        "search_text",
        "read_file",
        "read_tool_result",
        "search_symbol",
        "get_function",
        "get_class_by_name",
        "get_import_by_file",
    }
)


@dataclass
class AgentResult:
    content: str
    stop_reason: str = "complete"
    tool_calls: int = 0
    retries: int = 0
    compactions: int = 0
    receipts: list[dict[str, Any]] = field(default_factory=list)
    messages: list[Any] = field(default_factory=list)
    last_text: str = ""
    rounds: int = 0
    model_calls: int = 0
    calls: list[dict[str, Any]] = field(default_factory=list)
    elapsed_seconds: float = 0.0


def run_tool_loop(
    model: Any,
    system_prompt: str,
    user_prompt: str,
    tools: Iterable[Any] = (),
    *,
    budget: TaskBudget,
    usage: Any | None = None,
    stage: str = "agent",
    task_id: str = "task",
    max_rounds: int = 32,
    artifact_dir: Path | None = None,
    counter: TokenCounter | None = None,
    context: ContextManager | None = None,
    retry: RetryPolicy | None = None,
    json_expected: bool = False,
    json_repair_attempts: int = 1,
    max_result_tokens: int | None = None,
    request_timeout: float | None = None,
    parallel_tools: bool = False,
    finalize_on_exhaustion: bool = False,
    compaction_hint: Callable[[], str] | None = None,
    tool_store: ToolResultStore | None = None,
    model_semaphore: Any | None = None,
) -> AgentResult:
    """Synchronous entry point; the loop itself lives in ``run_tool_loop_async``."""
    return run_coroutine(
        run_tool_loop_async(
            model,
            system_prompt,
            user_prompt,
            tools,
            budget=budget,
            usage=usage,
            stage=stage,
            task_id=task_id,
            max_rounds=max_rounds,
            artifact_dir=artifact_dir,
            counter=counter,
            context=context,
            retry=retry,
            json_expected=json_expected,
            json_repair_attempts=json_repair_attempts,
            max_result_tokens=max_result_tokens,
            request_timeout=request_timeout,
            parallel_tools=parallel_tools,
            finalize_on_exhaustion=finalize_on_exhaustion,
            compaction_hint=compaction_hint,
            tool_store=tool_store,
            model_semaphore=model_semaphore,
        )
    )


async def run_tool_loop_async(
    model: Any,
    system_prompt: str,
    user_prompt: str,
    tools: Iterable[Any] = (),
    *,
    budget: Any,
    usage: Any | None = None,
    stage: str = "agent",
    task_id: str = "task",
    max_rounds: int = 32,
    artifact_dir: Path | None = None,
    counter: TokenCounter | None = None,
    context: ContextManager | None = None,
    retry: RetryPolicy | None = None,
    json_expected: bool = False,
    json_repair_attempts: int = 1,
    max_result_tokens: int | None = None,
    request_timeout: float | None = None,
    parallel_tools: bool = False,
    finalize_on_exhaustion: bool = False,
    compaction_hint: Callable[[], str] | None = None,
    tool_store: ToolResultStore | None = None,
    model_semaphore: Any | None = None,
) -> AgentResult:
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    tool_list = list(tools)
    counter = counter or TokenCounter()
    context = context or ContextManager(counter)
    retry = retry or RetryPolicy()
    store = tool_store
    if store is None and artifact_dir is not None:
        store = ToolResultStore(artifact_dir / "tool-results")
    if store is not None and not any(getattr(tool, "name", "") == "read_tool_result" for tool in tool_list):
        tool_list.append(
            StructuredTool.from_function(
                func=lambda ref, offset=0, limit=4000: store.read(ref, offset, limit),
                name="read_tool_result",
                description="Read a bounded window of a stored tool result by its artifact reference.",
            )
        )
    bound_model = model.bind_tools(tool_list) if tool_list and hasattr(model, "bind_tools") else model
    messages: list[Any] = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
    counters = {"tool_calls": 0, "retries": 0, "compactions": 0, "rounds": 0}
    receipts: list[dict[str, Any]] = []
    call_records: list[dict[str, Any]] = []
    last_text = ""
    last_tool_calls = 0

    for round_index in range(max(1, max_rounds) + 1):
        usage_reason = _usage_exceeded(usage)
        if usage_reason:
            if finalize_on_exhaustion:
                return await _finish_async(
                    model=model,
                    messages=messages,
                    budget=budget,
                    usage=usage,
                    stage=stage,
                    task_id=task_id,
                    counter=counter,
                    context=context,
                    request_timeout=request_timeout,
                    reason=usage_reason,
                    counters=counters,
                    receipts=receipts,
                    calls=call_records,
                    last_text=last_text,
                    semaphore=model_semaphore,
                    tool_calls=last_tool_calls,
                )
            raise BudgetStop(usage_reason)
        try:
            budget.check()
        except BudgetStop as exc:
            if finalize_on_exhaustion:
                return await _finish_async(
                    model=model,
                    messages=messages,
                    budget=budget,
                    usage=usage,
                    stage=stage,
                    task_id=task_id,
                    counter=counter,
                    context=context,
                    request_timeout=request_timeout,
                    reason=exc.reason,
                    counters=counters,
                    receipts=receipts,
                    calls=call_records,
                    last_text=last_text,
                    semaphore=model_semaphore,
                    tool_calls=last_tool_calls,
                )
            raise
        compaction_delta = 0
        if context.should_compact(messages):
            messages = context.compact(messages)
            counters["compactions"] += 1
            compaction_delta = 1
            if compaction_hint is not None:
                hint = compaction_hint()
                if hint:
                    messages.append(SystemMessage(content=hint))
        estimated = counter.count_messages(messages)
        before = budget.model_calls
        call_started = time.monotonic()
        try:
            response = await retry.model_async(
                lambda: _model_call_async(
                    bound_model,
                    messages,
                    budget,
                    request_timeout,
                    semaphore=model_semaphore,
                ),
                deadline=budget.deadline,
            )
        except BudgetStop as exc:
            if finalize_on_exhaustion:
                return await _finish_async(
                    model=model,
                    messages=messages,
                    budget=budget,
                    usage=usage,
                    stage=stage,
                    task_id=task_id,
                    counter=counter,
                    context=context,
                    request_timeout=request_timeout,
                    reason=exc.reason,
                    counters=counters,
                    receipts=receipts,
                    calls=call_records,
                    last_text=last_text,
                    semaphore=model_semaphore,
                    tool_calls=last_tool_calls,
                )
            raise
        except Exception as exc:
            raise _translate_model_error(exc) from exc
        attempts = max(1, budget.model_calls - before)
        counters["retries"] += max(0, attempts - 1)
        _record_usage(
            usage,
            stage,
            task_id,
            model,
            response,
            estimated,
            attempts,
            counters,
            tool_calls=last_tool_calls,
            compactions=compaction_delta,
        )
        call_records.append(_call_record(response, round_index, time.monotonic() - call_started))
        messages.append(response)
        counters["rounds"] += 1
        text = response_text(response)
        if text.strip():
            last_text = text
        calls = list(getattr(response, "tool_calls", []) or [])
        last_tool_calls = len(calls)
        if not calls:
            if json_expected and not _valid_json(text):
                repaired, repair_compactions, repair_retries = await _repair_json_async(
                    bound_model,
                    system_prompt,
                    text,
                    budget,
                    usage,
                    stage,
                    task_id,
                    model,
                    counter,
                    context,
                    request_timeout,
                    attempts=json_repair_attempts,
                    semaphore=model_semaphore,
                )
                counters["compactions"] += repair_compactions
                counters["retries"] += repair_retries
                text = repaired
            return AgentResult(
                content=text,
                tool_calls=counters["tool_calls"],
                retries=counters["retries"],
                compactions=counters["compactions"],
                receipts=receipts,
                calls=call_records,
                messages=messages,
                last_text=last_text,
                rounds=counters["rounds"],
                model_calls=int(getattr(budget, "model_calls", 0)),
            )
        if round_index >= max_rounds and finalize_on_exhaustion:
            return await _finish_async(
                model=model,
                messages=messages,
                budget=budget,
                usage=usage,
                stage=stage,
                task_id=task_id,
                counter=counter,
                context=context,
                request_timeout=request_timeout,
                reason="round_limit",
                counters=counters,
                receipts=receipts,
                calls=call_records,
                last_text=last_text,
                semaphore=model_semaphore,
            )
        try:
            results = await _execute_tools_async(
                calls, tool_list, budget=budget, retry=retry, parallel_tools=parallel_tools
            )
        except BudgetStop as exc:
            if finalize_on_exhaustion:
                return await _finish_async(
                    model=model,
                    messages=messages,
                    budget=budget,
                    usage=usage,
                    stage=stage,
                    task_id=task_id,
                    counter=counter,
                    context=context,
                    request_timeout=request_timeout,
                    reason=exc.reason,
                    counters=counters,
                    receipts=receipts,
                    calls=call_records,
                    last_text=last_text,
                    semaphore=model_semaphore,
                    tool_calls=last_tool_calls,
                )
            raise
        for call, result in zip(calls, results):
            counters["tool_calls"] += 1
            name = str(call.get("name") or "")
            arguments = parse_arguments(call.get("args", {}))
            content, receipt = render_result(
                tool=name,
                arguments=arguments,
                result=result,
                counter=counter,
                max_tokens=max(100, int(max_result_tokens)) if max_result_tokens else _max_result_tokens(),
                store=store,
            )
            receipts.append({**receipt, "round": round_index})
            messages.append(
                ToolMessage(
                    content=content,
                    tool_call_id=str(call.get("id") or name or "unknown"),
                )
            )
    if finalize_on_exhaustion:
        return await _finish_async(
            model=model,
            messages=messages,
            budget=budget,
            usage=usage,
            stage=stage,
            task_id=task_id,
            counter=counter,
            context=context,
            request_timeout=request_timeout,
            reason="round_limit",
            counters=counters,
            receipts=receipts,
            calls=call_records,
            last_text=last_text,
            semaphore=model_semaphore,
            tool_calls=last_tool_calls,
        )
    raise BudgetStop("round_limit")


async def _execute_tools_async(
    calls: list[dict[str, Any]],
    tool_list: list[Any],
    *,
    budget: Any,
    retry: RetryPolicy,
    parallel_tools: bool,
) -> list[Any]:
    by_name = {getattr(tool, "name", ""): tool for tool in tool_list}
    targets = [by_name.get(str(call.get("name") or "")) for call in calls]
    names = [str(call.get("name") or "") for call in calls]
    parallel = (
        parallel_tools
        and len(calls) > 1
        and all(name in _PARALLEL_TOOL_NAMES for name in names)
    )
    for _ in calls:
        budget.consume_tool_round()
    if parallel:
        return list(
            await asyncio.gather(
                *(
                    _execute_tool_async(tool, names[index], parse_arguments(call.get("args", {})), budget, retry)
                    for index, (tool, call) in enumerate(zip(targets, calls))
                ),
                return_exceptions=True,
            )
        )
    results: list[Any] = []
    for tool, name, call in zip(targets, names, calls):
        results.append(
            await _execute_tool_async(tool, name, parse_arguments(call.get("args", {})), budget, retry)
        )
    return results


async def _execute_tool_async(
    tool: Any, name: str, arguments: dict[str, Any], budget: Any, retry: RetryPolicy
) -> Any:
    if tool is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return await retry.tool_async(
            lambda: _invoke_tool_async(tool, arguments, getattr(budget, "deadline", None)),
            deadline=getattr(budget, "deadline", None),
        )
    except Exception as exc:
        return {"error": str(exc)}


async def _invoke_model_async(model: Any, messages: list[Any]) -> Any:
    # LangChain caches one process-global async httpx client on first use and binds it
    # to that event loop. Each stage runs in its own asyncio.run loop, so the second
    # loop to call the model reuses a closed client and raises "Event loop is closed".
    # The sync client carries no loop affinity, so prefer it.
    if hasattr(model, "invoke"):
        return await asyncio.to_thread(model.invoke, messages)
    return await model.ainvoke(messages)


async def _invoke_tool_async(tool: Any, arguments: dict[str, Any], deadline: float | None) -> Any:
    call = tool.ainvoke(arguments) if hasattr(tool, "ainvoke") else asyncio.to_thread(tool.invoke, arguments)
    if deadline is None:
        return await call
    remaining = max(0.001, deadline - time.monotonic())
    return await asyncio.wait_for(call, remaining)


async def _model_call_async(
    model: Any,
    messages: list[Any],
    budget: Any,
    request_timeout: float | None,
    *,
    charge_budget: bool = True,
    semaphore: Any | None = None,
) -> Any:
    if charge_budget:
        budget.consume_model_attempt()
    timeout = _call_timeout(budget, request_timeout)

    async def invoke() -> Any:
        if semaphore is None:
            return await _invoke_model_async(model, messages)
        async with semaphore:
            return await _invoke_model_async(model, messages)

    if timeout is None:
        return await invoke()
    return await asyncio.wait_for(invoke(), timeout)


def _usage_exceeded(usage: Any | None) -> str:
    if usage is None:
        return ""
    checker = getattr(usage, "exceeded", None)
    if not callable(checker):
        return ""
    return str(checker() or "")


def _call_timeout(budget: Any, request_timeout: float | None) -> float | None:
    remaining = budget.remaining_seconds() if hasattr(budget, "remaining_seconds") else None
    if remaining is not None and remaining <= 0:
        raise BudgetStop("time_budget")
    timeout = request_timeout if request_timeout and request_timeout > 0 else None
    if remaining is not None:
        timeout = remaining if timeout is None else min(timeout, remaining)
    return timeout


async def _finish_async(
    *,
    model: Any,
    messages: list[Any],
    budget: Any,
    usage: Any | None,
    stage: str,
    task_id: str,
    counter: TokenCounter,
    context: ContextManager,
    request_timeout: float | None,
    reason: str,
    counters: dict[str, int],
    receipts: list[dict[str, Any]],
    last_text: str,
    semaphore: Any | None = None,
    tool_calls: int = 0,
    calls: list[dict[str, Any]] | None = None,
) -> AgentResult:
    """Ask once for a tool-free final answer after the budget is spent."""
    from langchain_core.messages import HumanMessage, ToolMessage

    usage_reason = _usage_exceeded(usage)
    if usage_reason:
        return _result(
            reason=usage_reason,
            counters=counters,
            receipts=receipts,
            calls=calls,
            messages=messages,
            content=last_text,
            last_text=last_text,
            model_calls=int(getattr(budget, "model_calls", 0)),
        )
    remaining = budget.remaining_seconds() if hasattr(budget, "remaining_seconds") else None
    if remaining is not None and remaining <= 0:
        return _result(
            reason="time_budget",
            counters=counters,
            receipts=receipts,
            calls=calls,
            messages=messages,
            content=last_text,
            last_text=last_text,
            model_calls=int(getattr(budget, "model_calls", 0)),
        )
    pending: list[Any] = []
    last = messages[-1] if messages else None
    for call in getattr(last, "tool_calls", []) or []:
        pending.append(
            ToolMessage(
                content='{"status": "skipped", "error": "tool call skipped: budget exhausted"}',
                tool_call_id=str(call.get("id") or call.get("name") or "unknown"),
            )
        )
    finalize_messages = [
        *messages,
        *pending,
        HumanMessage(
            content=(
                "Tool budget exhausted. Do not call any tools. "
                "Return only the final JSON object now, using the source you have already read."
            )
        ),
    ]
    finalize_started = time.monotonic()
    try:
        response = await _model_call_async(
            model,
            finalize_messages,
            budget,
            request_timeout,
            charge_budget=False,
            semaphore=semaphore,
        )
    except Exception:
        return _result(
            reason=reason,
            counters=counters,
            receipts=receipts,
            calls=calls,
            messages=messages,
            content=last_text,
            last_text=last_text,
            model_calls=int(getattr(budget, "model_calls", 0)),
        )
    _record_usage(
        usage,
        stage,
        task_id,
        model,
        response,
        counter.count_messages(finalize_messages),
        1,
        counters,
        tool_calls=tool_calls,
        compactions=0,
    )
    calls = list(calls or [])
    calls.append(_call_record(response, "finalize", time.monotonic() - finalize_started))
    finalize_messages.append(response)
    content = response_text(response)
    return _result(
        reason=reason,
        counters=counters,
        receipts=receipts,
        calls=calls,
        messages=finalize_messages,
        content=content or last_text,
        last_text=content or last_text,
        model_calls=int(getattr(budget, "model_calls", 0)),
    )


def _result(
    *,
    reason: str,
    counters: dict[str, int],
    receipts: list[dict[str, Any]],
    messages: list[Any],
    content: str,
    last_text: str,
    model_calls: int = 0,
    calls: list[dict[str, Any]] | None = None,
) -> AgentResult:
    return AgentResult(
        content=content,
        stop_reason=reason,
        tool_calls=counters["tool_calls"],
        retries=counters["retries"],
        compactions=counters["compactions"],
        receipts=receipts,
        messages=messages,
        last_text=last_text,
        rounds=counters["rounds"],
        model_calls=model_calls,
        calls=list(calls or []),
    )


def run_coroutine(coro: Any) -> Any:
    """Run a coroutine from synchronous code, tolerating an active event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    result: list[Any] = []
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(coro))
        except BaseException as exc:  # pragma: no cover - only active-loop embedding
            error.append(exc)

    thread = threading.Thread(target=runner, name="agent-loop")
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


def _record_usage(
    usage: Any | None,
    stage: str,
    task_id: str,
    model: Any,
    response: Any,
    estimated: int,
    attempts: int,
    counters: dict[str, int],
    *,
    tool_calls: int | None = None,
    compactions: int | None = None,
) -> None:
    if usage is None:
        return
    metadata = getattr(response, "usage_metadata", None)
    usage.record(
        stage=stage,
        task_id=task_id,
        model=str(getattr(model, "model_name", getattr(model, "model", "")) or ""),
        usage=metadata,
        estimated_prompt_tokens=estimated,
        attempts=attempts,
        retries=max(0, attempts - 1),
        compactions=(
            counters["compactions"] if compactions is None else int(compactions)
        ),
        tool_calls=counters["tool_calls"] if tool_calls is None else int(tool_calls),
        source="provider" if metadata else "estimated",
    )


async def _repair_json_async(
    model: Any,
    system_prompt: str,
    content: str,
    budget: Any,
    usage: Any | None,
    stage: str,
    task_id: str,
    model_name: Any,
    counter: TokenCounter,
    context: ContextManager,
    request_timeout: float | None,
    *,
    attempts: int = 1,
    semaphore: Any | None = None,
) -> tuple[str, int, int]:
    from langchain_core.messages import HumanMessage, SystemMessage

    current = content
    total_attempts = 0
    for _ in range(max(1, int(attempts))):
        usage_reason = _usage_exceeded(usage)
        if usage_reason:
            raise BudgetStop(usage_reason)
        prompt = (
            "Your previous response was not a valid JSON object. "
            "Return only one JSON object, with no markdown fences or prose.\n\n"
            f"Previous response:\n{current[:12000]}"
        )
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=prompt)]
        before = budget.model_calls
        try:
            response = await _model_call_async(
                model,
                messages,
                budget,
                request_timeout,
                semaphore=semaphore,
            )
        except Exception as exc:
            raise _translate_model_error(exc) from exc
        total_attempts += max(1, budget.model_calls - before)
        _record_usage(
            usage,
            stage,
            task_id,
            model_name,
            response,
            counter.count_messages(messages),
            max(1, budget.model_calls - before),
            {"tool_calls": 0, "retries": 0, "compactions": 0},
            tool_calls=0,
            compactions=0,
        )
        current = response_text(response)
        if _valid_json(current):
            return current, 0, max(0, total_attempts - 1)
    raise ValueError("model did not return a JSON object after repair")


def _call_record(response: Any, round_index: int | str, duration: float) -> dict[str, Any]:
    metadata = getattr(response, "usage_metadata", None)
    prompt = completion = 0
    if isinstance(metadata, dict):
        prompt = int(metadata.get("input_tokens", 0) or 0)
        completion = int(metadata.get("output_tokens", 0) or 0)
    return {
        "round": round_index,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "usage_source": "provider" if metadata else "estimated",
        "duration_ms": round(duration * 1000, 1),
    }


def _max_result_tokens() -> int:
    import os

    try:
        return max(100, int(os.environ.get("AGENT_TOOL_RESULT_TOKENS", "2000")))
    except ValueError:
        return 2000


def response_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return str(content)


def _valid_json(value: str) -> bool:
    text = value.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, dict)


class ModelFatal(RuntimeError):
    """Fatal model configuration/auth failure."""


class ModelRequest(RuntimeError):
    """Non-fatal model request failure after retries."""


def _translate_model_error(error: Exception) -> Exception:
    from .retry import classify_model_error

    if isinstance(error, (BudgetStop, TimeoutError, ModelFatal, ModelRequest)):
        return error
    kind = classify_model_error(error)
    if kind == "fatal":
        return ModelFatal(str(error))
    if isinstance(error, TimeoutError):
        return error
    return ModelRequest(str(error))
