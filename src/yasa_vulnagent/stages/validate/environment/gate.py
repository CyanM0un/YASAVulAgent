"""Deterministic safety and structure checks for one environment plan."""

from __future__ import annotations

import copy
import shlex
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

from ....config import Settings
from .schema import plan_hash

_ALLOWED_INSTRUCTIONS = {
    "FROM",
    "ARG",
    "ENV",
    "WORKDIR",
    "COPY",
    "ADD",
    "RUN",
    "USER",
    "EXPOSE",
    "CMD",
    "ENTRYPOINT",
    "LABEL",
    "VOLUME",
    "HEALTHCHECK",
    "SHELL",
    "STOPSIGNAL",
}
_SECRET_NAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    ".npmrc",
    ".pypirc",
    ".netrc",
}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


def evaluate_plan(
    plan: Mapping[str, Any],
    receipts: Iterable[Mapping[str, Any]],
    settings: Settings,
) -> dict[str, Any]:
    """Return a gate decision without executing Docker or a model."""
    errors: list[dict[str, str]] = []
    warnings: list[str] = []
    clamps: list[str] = []
    effective = copy.deepcopy(dict(plan))
    declared_status = str(effective.get("status", "ready")).lower()
    if declared_status == "blocked":
        return {
            "status": "blocked",
            "hard_errors": [],
            "warnings": [],
            "clamps": [],
            "fallback_smoke": [],
            "effective_plan": effective,
        }
    if declared_status not in {"ready", "blocked"}:
        errors.append(_issue("plan_status_invalid", f"unsupported plan status: {declared_status}"))

    base_image = str(effective.get("base_image", "") or "").strip()
    if not base_image:
        errors.append(_issue("base_image_missing", "base_image is required"))
    instructions = effective.get("dockerfile")
    if not isinstance(instructions, list) or not instructions:
        errors.append(_issue("dockerfile_missing", "dockerfile instructions are required"))
        instructions = []
    parsed = _parse_instructions(instructions, errors, warnings)
    from_images = [item for item in parsed if item[0] == "FROM"]
    if not from_images:
        errors.append(_issue("from_missing", "Dockerfile must contain a FROM instruction"))
    if len(from_images) > 1:
        warnings.append("multi-stage build is used")
    if base_image and from_images:
        from_image = from_images[0][1].split()[0] if from_images[0][1].split() else ""
        if from_image and from_image != base_image:
            warnings.append(
                f"base_image {base_image!r} does not match the first FROM {from_image!r}"
            )
    _check_base_image(base_image, settings, errors, warnings)
    _check_instructions(parsed, errors, warnings)
    _check_evidence(effective, list(receipts), errors)
    smoke = _check_smoke(effective.get("smoke_commands"), base_image, warnings)
    if smoke:
        effective["smoke_commands"] = smoke
    elif not effective.get("smoke_commands"):
        errors.append(_issue("smoke_missing", "smoke commands are required or fallbackable"))
    else:
        errors.append(_issue("smoke_invalid", "smoke commands must be non-empty argv arrays"))
    _clamp_resources(effective, settings, clamps, warnings)

    if errors:
        status = "revise"
    else:
        status = "approved"
    return {
        "status": status,
        "hard_errors": errors,
        "warnings": _unique(warnings),
        "clamps": clamps,
        "fallback_smoke": smoke if not plan.get("smoke_commands") else [],
        "effective_plan": effective,
        "plan_hash": plan_hash(effective),
    }


def _parse_instructions(
    instructions: list[Any],
    errors: list[dict[str, str]],
    warnings: list[str],
) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for index, item in enumerate(instructions, start=1):
        if not isinstance(item, Mapping):
            errors.append(_issue("instruction_invalid", f"instruction {index} is not an object"))
            continue
        name = str(item.get("instruction", "") or "").strip().upper()
        arguments = str(item.get("arguments", "") or "").strip()
        if name not in _ALLOWED_INSTRUCTIONS:
            errors.append(_issue("instruction_unsupported", f"unsupported instruction {name!r}"))
            continue
        if not arguments:
            errors.append(_issue("instruction_empty", f"{name} has no arguments"))
            continue
        if "\n" in arguments or "\r" in arguments:
            errors.append(_issue("instruction_multiline", f"{name} arguments must be one line"))
            continue
        if name in {"EXPOSE", "VOLUME"}:
            warnings.append(f"{name} is recorded but not used by the smoke runtime")
        parsed.append((name, arguments))
    return parsed


def _check_base_image(
    base_image: str,
    settings: Settings,
    errors: list[dict[str, str]],
    warnings: list[str],
) -> None:
    if not base_image:
        return
    if not _valid_image_reference(base_image):
        errors.append(_issue("base_image_invalid", f"invalid base image reference: {base_image}"))
        return
    name = _image_name(base_image)
    allowed = name in {item.lower() for item in settings.validate_env_base_image_allowlist}
    if not allowed:
        message = f"base image {base_image!r} is not on the recommended allowlist"
        if settings.validate_env_gate_mode == "strict":
            errors.append(_issue("base_image_not_allowlisted", message))
        else:
            warnings.append(message)
    reference = base_image.rsplit("/", 1)[-1]
    if ":" not in reference or reference.rsplit(":", 1)[-1] == "latest":
        warnings.append(f"base image {base_image!r} is not pinned to an explicit tag")


def _check_instructions(
    parsed: list[tuple[str, str]],
    errors: list[dict[str, str]],
    warnings: list[str],
) -> None:
    for name, arguments in parsed:
        if name in {"COPY", "ADD"}:
            _check_copy(name, arguments, errors, warnings)
        elif name == "RUN":
            _check_run(arguments, errors, warnings)
        elif name == "USER":
            if arguments.strip().lower() in {"root", "0", "0:0"}:
                warnings.append("final Dockerfile USER is root; smoke runs with the image default user")
    if not any(name == "USER" for name, _ in parsed):
        warnings.append("Dockerfile does not set USER; the image default user may be root")


def _check_copy(
    name: str,
    arguments: str,
    errors: list[dict[str, str]],
    warnings: list[str],
) -> None:
    try:
        tokens = shlex.split(arguments)
    except ValueError as exc:
        errors.append(_issue("copy_invalid", f"{name} arguments are invalid: {exc}"))
        return
    from_stage = False
    filtered: list[str] = []
    for token in tokens:
        if token.startswith("--from="):
            from_stage = True
            continue
        if token.startswith("--"):
            continue
        filtered.append(token)
    if len(filtered) < 2:
        errors.append(_issue("copy_invalid", f"{name} needs at least one source and one destination"))
        return
    sources = filtered[:-1]
    for source in sources:
        if source.startswith(("http://", "https://", "git@")):
            if name == "ADD":
                warnings.append(f"ADD downloads a remote resource: {source}")
                continue
            errors.append(_issue("copy_remote", "COPY cannot use a remote source"))
            continue
        if from_stage:
            continue
        if PurePosixPath(source).is_absolute() or any(part == ".." for part in PurePosixPath(source).parts):
            errors.append(_issue("copy_path_escape", f"{name} source escapes the build context: {source}"))
            continue
        if _secret_path(source):
            errors.append(_issue("copy_secret", f"{name} copies a secret-like path: {source}"))


def _check_run(
    arguments: str,
    errors: list[dict[str, str]],
    warnings: list[str],
) -> None:
    lowered = arguments.lower()
    for token in ("nsenter", "pivot_root", "umount", "mount "):
        if token in lowered:
            errors.append(_issue("host_escape_command", f"RUN contains host escape command: {token.strip()}"))
    if "docker.sock" in lowered or "/var/run/docker" in lowered:
        errors.append(_issue("container_socket", "RUN references the Docker socket"))
    if "--security=insecure" in lowered:
        errors.append(_issue("buildkit_insecure", "RUN requests an insecure BuildKit sandbox"))
    if "--mount=type=secret" in lowered or "--mount=type=ssh" in lowered:
        errors.append(_issue("buildkit_secret", "RUN requests a BuildKit secret or SSH mount"))
    if "--mount=type=bind" in lowered and (
        "source=/" in lowered or "source=.." in lowered
    ):
        errors.append(_issue("buildkit_host_bind", "RUN binds a host path into the build"))
    if "sudo " in lowered or lowered.startswith("sudo"):
        warnings.append("RUN uses sudo; the build container is already privileged enough to install packages")
    if "apt-get install" in lowered and "rm -rf /var/lib/apt/lists" not in lowered:
        warnings.append("RUN installs apt packages without cleaning the apt lists")
    if "curl" in lowered and "|" in lowered and ("sh" in lowered or "bash" in lowered):
        warnings.append("RUN pipes a remote download into a shell; record this supply-chain risk")
    if "docker " in lowered or lowered.startswith("docker "):
        warnings.append("RUN invokes docker inside the build container")


def _check_evidence(
    plan: Mapping[str, Any],
    receipts: list[Mapping[str, Any]],
    errors: list[dict[str, str]],
) -> None:
    inspection = plan.get("inspection")
    evidence = inspection.get("evidence") if isinstance(inspection, Mapping) else None
    if not isinstance(evidence, list) or not evidence:
        errors.append(_issue("evidence_missing", "inspection.evidence must cite files read by the agent"))
        return
    read_receipts = [
        item
        for item in receipts
        if str(item.get("tool", "")) == "read_file"
        and str(item.get("status", "ok")) == "ok"
        and not item.get("truncated")
    ]
    if not read_receipts:
        errors.append(_issue("evidence_not_read", "the plan has no successful read_file receipts"))
        return
    for item in evidence:
        if not isinstance(item, Mapping):
            errors.append(_issue("evidence_invalid", "evidence item is not an object"))
            continue
        path = str(item.get("path", "") or "")
        start = _line_number(item.get("start_line"))
        end = _line_number(item.get("end_line"))
        if not path or start is None or end is None or end < start:
            errors.append(_issue("evidence_invalid", "evidence needs path, start_line and end_line"))
            continue
        if _secret_path(path):
            errors.append(_issue("evidence_secret", f"evidence cites a secret-like path: {path}"))
            continue
        covered = any(
            str(receipt.get("path", "")) == path
            and _line_number(receipt.get("start_line")) is not None
            and _line_number(receipt.get("end_line")) is not None
            and int(receipt["start_line"]) <= start
            and (
                int(receipt["end_line"]) >= end
                or (
                    _line_number(receipt.get("total_lines")) is not None
                    and start <= int(receipt["total_lines"])
                    and int(receipt["end_line"]) >= int(receipt["total_lines"])
                )
            )
            for receipt in read_receipts
        )
        if not covered:
            errors.append(
                _issue("evidence_not_read", f"evidence range {path}:{start}-{end} was not read")
            )


def _check_smoke(
    commands: Any,
    base_image: str,
    warnings: list[str],
) -> list[list[str]]:
    if commands is not None and not isinstance(commands, list):
        return []
    if isinstance(commands, list) and commands:
        valid: list[list[str]] = []
        for command in commands:
            if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
                continue
            valid.append([str(item) for item in command])
        return valid
    fallback = _fallback_smoke(base_image)
    if fallback:
        warnings.append("smoke commands were missing; a deterministic fallback smoke was added")
        return fallback
    return []


def _fallback_smoke(base_image: str) -> list[list[str]]:
    name = _image_name(base_image)
    if name.startswith(("python", "pypy")):
        return [["python", "-m", "compileall", "-q", "."]]
    if name.startswith("node"):
        return [["node", "-e", "require('./package.json')"]]
    if name.startswith(("golang", "go")):
        return [["go", "test", "./...", "-run", "^$"]]
    return []


def _clamp_resources(
    plan: dict[str, Any],
    settings: Settings,
    clamps: list[str],
    warnings: list[str],
) -> None:
    resources = plan.get("resources")
    if not isinstance(resources, dict):
        return
    cpus = _number(resources.get("cpus"))
    pids = _number(resources.get("pids"))
    timeout = _number(resources.get("timeout"))
    if cpus is not None and cpus > settings.validate_docker_cpus:
        resources["cpus"] = settings.validate_docker_cpus
        clamps.append(f"cpus clamped to {settings.validate_docker_cpus}")
    if pids is not None and pids > settings.validate_docker_pids:
        resources["pids"] = settings.validate_docker_pids
        clamps.append(f"pids clamped to {settings.validate_docker_pids}")
    if timeout is not None and timeout > settings.validate_docker_smoke_timeout:
        resources["timeout"] = settings.validate_docker_smoke_timeout
        clamps.append(f"timeout clamped to {settings.validate_docker_smoke_timeout}")
    if clamps:
        warnings.extend(clamps)


def _image_name(reference: str) -> str:
    value = reference.split("@", 1)[0]
    last = value.rsplit("/", 1)[-1]
    return last.split(":", 1)[0].lower()


def _valid_image_reference(reference: str) -> bool:
    if not reference or reference.startswith(("/", ".", "-")):
        return False
    return not any(character.isspace() for character in reference)


def _secret_path(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in _SECRET_NAMES or name.endswith(_SECRET_SUFFIXES) or name.startswith(".env.")


def _line_number(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 1 else None


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _issue(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def gate_node(state: Mapping[str, Any], runtime: Any | None = None) -> dict[str, Any]:
    """Run the deterministic gate and route to build or back to plan."""
    from ....workflow.state import RunContext
    from .storage import gate_file, plan_effective_file, write_json

    context = runtime.context if runtime is not None else None
    if context is None:
        from ....config import load_settings

        context = RunContext(settings=load_settings())
    settings = context.settings
    plan = dict(state.get("plan") or {})
    decision = evaluate_plan(plan, state.get("plan_receipts", []), settings)
    revision = int(state.get("plan_revision", 0))
    write_json(gate_file(state, revision), decision)
    gate_rejections = int(state.get("gate_rejections", 0))
    previous_hash = str(state.get("last_gate_hash", ""))
    decision_hash = str(decision.get("plan_hash", ""))
    status = str(decision.get("status", "revise"))

    if status == "blocked":
        return {
            **dict(state),
            "gate": decision,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "plan_blocked",
            "gaps": _unique([*state.get("gaps", []), *[item.get("message", "") for item in decision.get("hard_errors", [])]]),
        }
    if status == "approved":
        effective = dict(decision.get("effective_plan") or plan)
        write_json(plan_effective_file(state, revision), effective)
        return {
            **dict(state),
            "gate": decision,
            "approved_plan": effective,
            "plan_hash": decision_hash,
            "last_gate_hash": decision_hash,
            "warnings": _unique([*state.get("warnings", []), *decision.get("warnings", [])]),
            "next_action": "build",
        }

    gate_rejections += 1
    if gate_rejections > settings.validate_env_max_gate_revisions or (
        previous_hash and previous_hash == decision_hash
    ):
        return {
            **dict(state),
            "gate": decision,
            "gate_rejections": gate_rejections,
            "status": "blocked",
            "next_action": "classify",
            "stop_reason": "gate_stagnation",
            "gaps": _unique([*state.get("gaps", []), *[item.get("message", "") for item in decision.get("hard_errors", [])]]),
        }
    return {
        **dict(state),
        "gate": decision,
        "gate_rejections": gate_rejections,
        "last_gate_hash": decision_hash,
        "warnings": _unique([*state.get("warnings", []), *decision.get("warnings", [])]),
        "next_action": "plan",
    }
