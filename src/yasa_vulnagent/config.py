from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-flash"
DEFAULT_CWE_ARCHIVE_PATH = Path(".knowledge") / "cwe-top25-1435.xml.zip"
DEFAULT_YASA_SOURCE_PATH = Path("tools") / "yasa-mcp"
DEFAULT_YASA_BIN_PATH = Path("tools") / "yasa"
DEFAULT_YASA_INIT_TIMEOUT = 3600
DEFAULT_YASA_STATUS_TIMEOUT = 120
DEFAULT_YASA_MCP_TIMEOUT = 60
DEFAULT_DOCUMENTS_TIMEOUT = 1800
DEFAULT_DOCUMENTS_MODEL_TIMEOUT = 60
DEFAULT_DOCUMENTS_FETCH_TIMEOUT = 30
DEFAULT_DOCUMENTS_CHUNK_CHARS = 12000
DEFAULT_DOCUMENTS_CONTEXT_CHARS = 60000
DEFAULT_DOCUMENTS_SUMMARY_RESERVE = 180
DEFAULT_HISTORY_TIMEOUT = 3600
DEFAULT_HISTORY_DISCOVERY_TIMEOUT = 600
DEFAULT_HISTORY_TASK_TIMEOUT = 600
DEFAULT_HISTORY_MODEL_TIMEOUT = 60
DEFAULT_HISTORY_SUMMARY_RESERVE = 120
DEFAULT_HISTORY_MAX_AGENTS = 3
DEFAULT_HISTORY_DIFF_CHARS = 24000
DEFAULT_SCREEN_WAVE_TIMEOUT = 1200
DEFAULT_SCREEN_WAVE_MODEL_CALLS = 96
DEFAULT_SCREEN_TOOL_OUTPUT_CHARS = 12000
DEFAULT_SCREEN_CONTEXT_CHARS = 40000
DEFAULT_SCREEN_TASK_MAX_ROUNDS = 16
DEFAULT_DISCOVER_RECURSION_LIMIT = 50
DEFAULT_DISCOVER_CONTEXT_TOKENS = 10000
DEFAULT_DISCOVER_REQUEST_TIMEOUT = 180
DEFAULT_DISCOVER_SEARCH_MAX_FILE_BYTES = 2_097_152
DEFAULT_DISCOVER_SEARCH_MAX_SCAN_FILES = 2000
DEFAULT_DISCOVER_NOTES_MAX = 20
DEFAULT_DISCOVER_NOTE_CHARS = 2000
DEFAULT_SCREEN_WAVE_MAX_TASKS = 6
DEFAULT_AUDIT_MODE = "combined"
DEFAULT_AUDIT_TIMEOUT = 3600
DEFAULT_AUDIT_RECURSION_LIMIT = 50
DEFAULT_AUDIT_MAX_AGENTS = 4
DEFAULT_AUDIT_PLAN_BATCH_SIZE = 100
DEFAULT_AUDIT_MAX_TOTAL_TOKENS = 0
DEFAULT_AUDIT_MAX_TOTAL_COST = 0.0
DEFAULT_AUDIT_MODEL_CONCURRENCY = 4
AUDIT_MODES = ("entries", "patches", "combined")
VALIDATE_ENV_GATE_MODES = ("balanced", "strict", "permissive")
DEFAULT_VALIDATE_ENV_MODEL = ""
DEFAULT_VALIDATE_ENV_GATE_MODE = "balanced"
DEFAULT_VALIDATE_ENV_MAX_PLAN_CALLS = 5
DEFAULT_VALIDATE_ENV_MAX_DIAGNOSE_CALLS = 3
DEFAULT_VALIDATE_ENV_MAX_BUILD_ATTEMPTS = 3
DEFAULT_VALIDATE_ENV_MAX_PLAN_REVISIONS = 3
DEFAULT_VALIDATE_ENV_MAX_GATE_REVISIONS = 2
DEFAULT_VALIDATE_ENV_LLM_TIMEOUT = 300
DEFAULT_VALIDATE_ENV_AGENT_MAX_ROUNDS = 24
DEFAULT_VALIDATE_ENV_AGENT_MAX_CALLS = 24
DEFAULT_VALIDATE_ENV_TOOL_OUTPUT_CHARS = 12000
DEFAULT_VALIDATE_ENV_CONTEXT_CHARS = 50000
DEFAULT_VALIDATE_ENV_MAX_CONTEXT_BYTES = 1_073_741_824
DEFAULT_VALIDATE_ENV_MAX_CONTEXT_FILES = 20000
DEFAULT_VALIDATE_ENV_RECURSION_LIMIT = 50
DEFAULT_VALIDATE_ENV_BASE_IMAGE_ALLOWLIST = (
    "python",
    "node",
    "golang",
    "rust",
    "openjdk",
    "debian",
    "ubuntu",
    "alpine",
)
DEFAULT_VALIDATE_DOCKER_BIN = "docker"
DEFAULT_VALIDATE_DOCKER_HOST = ""
DEFAULT_VALIDATE_DOCKER_PULL = "never"
DEFAULT_VALIDATE_DOCKER_PLATFORM = ""
DEFAULT_VALIDATE_DOCKER_BUILD_TIMEOUT = 1800
DEFAULT_VALIDATE_DOCKER_SMOKE_TIMEOUT = 120
DEFAULT_VALIDATE_DOCKER_MEMORY = "2g"
DEFAULT_VALIDATE_DOCKER_CPUS = 2.0
DEFAULT_VALIDATE_DOCKER_PIDS = 256
DEFAULT_VALIDATE_DOCKER_LOG_BYTES = 10_000_000
DEFAULT_VALIDATE_MODEL = ""
DEFAULT_VALIDATE_LLM_TIMEOUT = 300
DEFAULT_VALIDATE_AGENT_MAX_ROUNDS = 32
DEFAULT_VALIDATE_AGENT_MAX_CALLS = 64
DEFAULT_VALIDATE_TOOL_OUTPUT_CHARS = 12000
DEFAULT_VALIDATE_COMMAND_TIMEOUT = 600
DEFAULT_VALIDATE_TOTAL_TIMEOUT = 1800
DEFAULT_VALIDATE_MAX_TOTAL_TOKENS = 0
DEFAULT_VALIDATE_MAX_TOTAL_COST = 0.0
DEFAULT_REPORT_MODEL = ""
DEFAULT_REPORT_LANGUAGE = "en"
DEFAULT_REPORT_LLM_TIMEOUT = 300
DEFAULT_REPORT_TOTAL_TIMEOUT = 900
DEFAULT_REPORT_MAX_TOTAL_TOKENS = 0
DEFAULT_REPORT_MAX_TOTAL_COST = 0.0
DEFAULT_REPORT_MAX_FINDINGS = 10
DEFAULT_PLANNER_MODEL = ""
DEFAULT_PLANNER_MAX_CALLS = 6
DEFAULT_PLANNER_MAX_NEW_TASKS = 2
DEFAULT_PLANNER_MAX_FILES = 8
DEFAULT_PLANNER_MAX_CHARS = 40000
DEFAULT_REVIEW_MODEL = ""
DEFAULT_REVIEW_MAX_CALLS = 8
DEFAULT_REVIEW_TIMEOUT = 300
DEFAULT_REVIEW_STAGNATION_WAVES = 3
DEFAULT_FEATURE_MAX_RESULTS = 200
DEFAULT_FEATURE_MAX_TASKS = 32
DEFAULT_FEATURE_QUERY_TIMEOUT = 30
DEFAULT_FEATURE_MAX_REGEX_CHARS = 512
DEFAULT_CONFIRM_MODEL = ""
DEFAULT_CONFIRM_TIMEOUT = 600
DEFAULT_CONFIRM_MAX_CALLS = 32
DEFAULT_CONFIRM_MAX_TASKS = 6
DEFAULT_CONFIRM_MAX_CANDIDATES = 8
DEFAULT_CONFIRM_MAX_SAME_FILE = 4
DEFAULT_AGENT_MAX_ROUNDS_PER_INVOCATION = 32
DEFAULT_DOCUMENTS_MAX_MODEL_CALLS = 96
DEFAULT_DOCUMENTS_DISCOVERY_MAX_MODEL_CALLS = 32
DEFAULT_DOCUMENTS_SUMMARY_MAX_MODEL_CALLS = 16
DEFAULT_HISTORY_MAX_MODEL_CALLS = 32
DEFAULT_HISTORY_DISCOVERY_MAX_MODEL_CALLS = 32
DEFAULT_HISTORY_SUMMARY_MAX_MODEL_CALLS = 16
DEFAULT_PATCH_MAX_MODEL_CALLS = 24
DEFAULT_AGENT_HARD_TASK_CAP = 128
DEFAULT_AGENT_TOOL_RESULT_TOKENS = 2000
DEFAULT_AGENT_KEEP_RECENT_RESULTS = 3
DEFAULT_AGENT_CONTEXT_TOKENS = 40000
DEFAULT_AGENT_COMPACTION_TRIGGER = 0.8
DEFAULT_AGENT_TOKEN_SAFETY = 1.2
DEFAULT_TOOLS_FS_READ_TIMEOUT = 10
DEFAULT_TOOLS_FS_SEARCH_TIMEOUT = 30
DEFAULT_TOOLS_GIT_TIMEOUT = 30
DEFAULT_TOOLS_HTTP_TIMEOUT = 30
DEFAULT_TOOLS_HTTP_MAX_BYTES = 2_000_000
DEFAULT_DOCUMENTS_MAX_TEXT_BYTES = 2_000_000
DEFAULT_DOCUMENTS_MAX_PDF_BYTES = 50_000_000
DEFAULT_DOCUMENTS_MAX_PDF_PAGES = 300
DEFAULT_DOCUMENTS_MAX_DOCX_BYTES = 20_000_000
DEFAULT_DOCUMENTS_MAX_DOCX_BLOCKS = 5000
DEFAULT_AGENT_CACHE_BYTES = 64_000_000
DEFAULT_AGENT_MODEL_RETRIES = 3
DEFAULT_AGENT_JSON_REPAIR_ATTEMPTS = 1
DEFAULT_AGENT_TOOL_RETRIES = 1
DEFAULT_DOCUMENTS_AGENT_CHUNK_TOKENS = 1500
DEFAULT_DOCUMENTS_READ_MODE = "auto"


def resolve_project_path(path: str | Path) -> Path:
    """Resolve a relative bundled-tool path from the new project root."""
    candidate = Path(path).expanduser()
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the migrated workflow stages."""

    api_key: str | None
    base_url: str
    model: str
    cwe_archive_path: Path = DEFAULT_CWE_ARCHIVE_PATH
    yasa_source_path: Path = DEFAULT_YASA_SOURCE_PATH
    yasa_bin_path: Path = DEFAULT_YASA_BIN_PATH
    yasa_init_timeout: int = DEFAULT_YASA_INIT_TIMEOUT
    yasa_status_timeout: int = DEFAULT_YASA_STATUS_TIMEOUT
    yasa_mcp_timeout: int = DEFAULT_YASA_MCP_TIMEOUT
    documents_timeout: int = DEFAULT_DOCUMENTS_TIMEOUT
    documents_model_timeout: int = DEFAULT_DOCUMENTS_MODEL_TIMEOUT
    documents_fetch_timeout: int = DEFAULT_DOCUMENTS_FETCH_TIMEOUT
    documents_chunk_chars: int = DEFAULT_DOCUMENTS_CHUNK_CHARS
    documents_context_chars: int = DEFAULT_DOCUMENTS_CONTEXT_CHARS
    documents_summary_reserve: int = DEFAULT_DOCUMENTS_SUMMARY_RESERVE
    history_timeout: int = DEFAULT_HISTORY_TIMEOUT
    history_discovery_timeout: int = DEFAULT_HISTORY_DISCOVERY_TIMEOUT
    history_task_timeout: int = DEFAULT_HISTORY_TASK_TIMEOUT
    history_model_timeout: int = DEFAULT_HISTORY_MODEL_TIMEOUT
    history_summary_reserve: int = DEFAULT_HISTORY_SUMMARY_RESERVE
    history_max_agents: int = DEFAULT_HISTORY_MAX_AGENTS
    history_diff_chars: int = DEFAULT_HISTORY_DIFF_CHARS
    screen_wave_timeout: int = DEFAULT_SCREEN_WAVE_TIMEOUT
    screen_wave_model_calls: int = DEFAULT_SCREEN_WAVE_MODEL_CALLS
    screen_tool_output_chars: int = DEFAULT_SCREEN_TOOL_OUTPUT_CHARS
    screen_context_chars: int = DEFAULT_SCREEN_CONTEXT_CHARS
    discover_context_tokens: int = DEFAULT_DISCOVER_CONTEXT_TOKENS
    discover_request_timeout: int = DEFAULT_DISCOVER_REQUEST_TIMEOUT
    discover_search_max_file_bytes: int = DEFAULT_DISCOVER_SEARCH_MAX_FILE_BYTES
    discover_search_max_scan_files: int = DEFAULT_DISCOVER_SEARCH_MAX_SCAN_FILES
    discover_notes_max: int = DEFAULT_DISCOVER_NOTES_MAX
    discover_note_chars: int = DEFAULT_DISCOVER_NOTE_CHARS
    screen_wave_max_tasks: int = DEFAULT_SCREEN_WAVE_MAX_TASKS
    screen_task_max_rounds: int = DEFAULT_SCREEN_TASK_MAX_ROUNDS
    discover_recursion_limit: int = DEFAULT_DISCOVER_RECURSION_LIMIT
    audit_mode: str = DEFAULT_AUDIT_MODE
    audit_timeout: int = DEFAULT_AUDIT_TIMEOUT
    audit_recursion_limit: int = DEFAULT_AUDIT_RECURSION_LIMIT
    audit_max_agents: int = DEFAULT_AUDIT_MAX_AGENTS
    audit_plan_batch_size: int = DEFAULT_AUDIT_PLAN_BATCH_SIZE
    audit_max_total_tokens: int = DEFAULT_AUDIT_MAX_TOTAL_TOKENS
    audit_max_total_cost: float = DEFAULT_AUDIT_MAX_TOTAL_COST
    audit_model_concurrency: int = DEFAULT_AUDIT_MODEL_CONCURRENCY
    validate_env_model: str = DEFAULT_VALIDATE_ENV_MODEL
    validate_env_gate_mode: str = DEFAULT_VALIDATE_ENV_GATE_MODE
    validate_env_max_plan_calls: int = DEFAULT_VALIDATE_ENV_MAX_PLAN_CALLS
    validate_env_max_diagnose_calls: int = DEFAULT_VALIDATE_ENV_MAX_DIAGNOSE_CALLS
    validate_env_max_build_attempts: int = DEFAULT_VALIDATE_ENV_MAX_BUILD_ATTEMPTS
    validate_env_max_plan_revisions: int = DEFAULT_VALIDATE_ENV_MAX_PLAN_REVISIONS
    validate_env_max_gate_revisions: int = DEFAULT_VALIDATE_ENV_MAX_GATE_REVISIONS
    validate_env_llm_timeout: int = DEFAULT_VALIDATE_ENV_LLM_TIMEOUT
    validate_env_agent_max_rounds: int = DEFAULT_VALIDATE_ENV_AGENT_MAX_ROUNDS
    validate_env_agent_max_calls: int = DEFAULT_VALIDATE_ENV_AGENT_MAX_CALLS
    validate_env_tool_output_chars: int = DEFAULT_VALIDATE_ENV_TOOL_OUTPUT_CHARS
    validate_env_context_chars: int = DEFAULT_VALIDATE_ENV_CONTEXT_CHARS
    validate_env_max_context_bytes: int = DEFAULT_VALIDATE_ENV_MAX_CONTEXT_BYTES
    validate_env_max_context_files: int = DEFAULT_VALIDATE_ENV_MAX_CONTEXT_FILES
    validate_env_recursion_limit: int = DEFAULT_VALIDATE_ENV_RECURSION_LIMIT
    validate_env_base_image_allowlist: tuple[str, ...] = DEFAULT_VALIDATE_ENV_BASE_IMAGE_ALLOWLIST
    validate_docker_bin: str = DEFAULT_VALIDATE_DOCKER_BIN
    validate_docker_host: str = DEFAULT_VALIDATE_DOCKER_HOST
    validate_docker_pull: str = DEFAULT_VALIDATE_DOCKER_PULL
    validate_docker_platform: str = DEFAULT_VALIDATE_DOCKER_PLATFORM
    validate_docker_build_timeout: int = DEFAULT_VALIDATE_DOCKER_BUILD_TIMEOUT
    validate_docker_smoke_timeout: int = DEFAULT_VALIDATE_DOCKER_SMOKE_TIMEOUT
    validate_docker_memory: str = DEFAULT_VALIDATE_DOCKER_MEMORY
    validate_docker_cpus: float = DEFAULT_VALIDATE_DOCKER_CPUS
    validate_docker_pids: int = DEFAULT_VALIDATE_DOCKER_PIDS
    validate_docker_log_bytes: int = DEFAULT_VALIDATE_DOCKER_LOG_BYTES
    validate_model: str = DEFAULT_VALIDATE_MODEL
    validate_llm_timeout: int = DEFAULT_VALIDATE_LLM_TIMEOUT
    validate_agent_max_rounds: int = DEFAULT_VALIDATE_AGENT_MAX_ROUNDS
    validate_agent_max_calls: int = DEFAULT_VALIDATE_AGENT_MAX_CALLS
    validate_tool_output_chars: int = DEFAULT_VALIDATE_TOOL_OUTPUT_CHARS
    validate_command_timeout: int = DEFAULT_VALIDATE_COMMAND_TIMEOUT
    validate_total_timeout: int = DEFAULT_VALIDATE_TOTAL_TIMEOUT
    validate_max_total_tokens: int = DEFAULT_VALIDATE_MAX_TOTAL_TOKENS
    validate_max_total_cost: float = DEFAULT_VALIDATE_MAX_TOTAL_COST
    report_model: str = DEFAULT_REPORT_MODEL
    report_language: str = DEFAULT_REPORT_LANGUAGE
    report_llm_timeout: int = DEFAULT_REPORT_LLM_TIMEOUT
    report_total_timeout: int = DEFAULT_REPORT_TOTAL_TIMEOUT
    report_max_total_tokens: int = DEFAULT_REPORT_MAX_TOTAL_TOKENS
    report_max_total_cost: float = DEFAULT_REPORT_MAX_TOTAL_COST
    report_max_findings: int = DEFAULT_REPORT_MAX_FINDINGS
    planner_model: str = DEFAULT_PLANNER_MODEL
    planner_max_calls: int = DEFAULT_PLANNER_MAX_CALLS
    planner_max_new_tasks: int = DEFAULT_PLANNER_MAX_NEW_TASKS
    planner_max_files: int = DEFAULT_PLANNER_MAX_FILES
    planner_max_chars: int = DEFAULT_PLANNER_MAX_CHARS
    review_model: str = DEFAULT_REVIEW_MODEL
    review_max_calls: int = DEFAULT_REVIEW_MAX_CALLS
    review_timeout: int = DEFAULT_REVIEW_TIMEOUT
    review_stagnation_waves: int = DEFAULT_REVIEW_STAGNATION_WAVES
    feature_max_results: int = DEFAULT_FEATURE_MAX_RESULTS
    feature_max_tasks: int = DEFAULT_FEATURE_MAX_TASKS
    feature_query_timeout: int = DEFAULT_FEATURE_QUERY_TIMEOUT
    feature_max_regex_chars: int = DEFAULT_FEATURE_MAX_REGEX_CHARS
    confirm_model: str = DEFAULT_CONFIRM_MODEL
    confirm_timeout: int = DEFAULT_CONFIRM_TIMEOUT
    confirm_max_calls: int = DEFAULT_CONFIRM_MAX_CALLS
    confirm_max_tasks: int = DEFAULT_CONFIRM_MAX_TASKS
    confirm_max_candidates: int = DEFAULT_CONFIRM_MAX_CANDIDATES
    confirm_max_same_file: int = DEFAULT_CONFIRM_MAX_SAME_FILE
    agent_max_rounds_per_invocation: int = DEFAULT_AGENT_MAX_ROUNDS_PER_INVOCATION
    documents_max_model_calls: int = DEFAULT_DOCUMENTS_MAX_MODEL_CALLS
    documents_discovery_max_model_calls: int = DEFAULT_DOCUMENTS_DISCOVERY_MAX_MODEL_CALLS
    documents_summary_max_model_calls: int = DEFAULT_DOCUMENTS_SUMMARY_MAX_MODEL_CALLS
    history_max_model_calls: int = DEFAULT_HISTORY_MAX_MODEL_CALLS
    history_discovery_max_model_calls: int = DEFAULT_HISTORY_DISCOVERY_MAX_MODEL_CALLS
    history_summary_max_model_calls: int = DEFAULT_HISTORY_SUMMARY_MAX_MODEL_CALLS
    patch_max_model_calls: int = DEFAULT_PATCH_MAX_MODEL_CALLS
    agent_hard_task_cap: int = DEFAULT_AGENT_HARD_TASK_CAP
    agent_tool_result_tokens: int = DEFAULT_AGENT_TOOL_RESULT_TOKENS
    agent_keep_recent_results: int = DEFAULT_AGENT_KEEP_RECENT_RESULTS
    agent_context_tokens: int = DEFAULT_AGENT_CONTEXT_TOKENS
    agent_compaction_trigger: float = DEFAULT_AGENT_COMPACTION_TRIGGER
    agent_token_safety: float = DEFAULT_AGENT_TOKEN_SAFETY
    tools_fs_read_timeout: int = DEFAULT_TOOLS_FS_READ_TIMEOUT
    tools_fs_search_timeout: int = DEFAULT_TOOLS_FS_SEARCH_TIMEOUT
    tools_git_timeout: int = DEFAULT_TOOLS_GIT_TIMEOUT
    tools_http_timeout: int = DEFAULT_TOOLS_HTTP_TIMEOUT
    tools_http_max_bytes: int = DEFAULT_TOOLS_HTTP_MAX_BYTES
    documents_max_text_bytes: int = DEFAULT_DOCUMENTS_MAX_TEXT_BYTES
    documents_max_pdf_bytes: int = DEFAULT_DOCUMENTS_MAX_PDF_BYTES
    documents_max_pdf_pages: int = DEFAULT_DOCUMENTS_MAX_PDF_PAGES
    documents_max_docx_bytes: int = DEFAULT_DOCUMENTS_MAX_DOCX_BYTES
    documents_max_docx_blocks: int = DEFAULT_DOCUMENTS_MAX_DOCX_BLOCKS
    agent_cache_bytes: int = DEFAULT_AGENT_CACHE_BYTES
    agent_model_retries: int = DEFAULT_AGENT_MODEL_RETRIES
    agent_json_repair_attempts: int = DEFAULT_AGENT_JSON_REPAIR_ATTEMPTS
    agent_tool_retries: int = DEFAULT_AGENT_TOOL_RETRIES
    documents_agent_chunk_tokens: int = DEFAULT_DOCUMENTS_AGENT_CHUNK_TOKENS
    documents_read_mode: str = DEFAULT_DOCUMENTS_READ_MODE
    usage_price_table: Path | None = None

    def safe_dict(self) -> dict[str, object]:
        """Return configuration metadata without exposing the API key."""
        return {
            "api_key_configured": bool(self.api_key),
            "base_url": self.base_url,
            "model": self.model,
            "cwe_archive_path": str(self.cwe_archive_path),
            "yasa_source_path": str(self.yasa_source_path),
            "yasa_bin_path": str(self.yasa_bin_path),
            "yasa_init_timeout": self.yasa_init_timeout,
            "yasa_status_timeout": self.yasa_status_timeout,
            "yasa_mcp_timeout": self.yasa_mcp_timeout,
            "documents_timeout": self.documents_timeout,
            "documents_model_timeout": self.documents_model_timeout,
            "documents_fetch_timeout": self.documents_fetch_timeout,
            "documents_chunk_chars": self.documents_chunk_chars,
            "documents_context_chars": self.documents_context_chars,
            "documents_summary_reserve": self.documents_summary_reserve,
            "history_timeout": self.history_timeout,
            "history_discovery_timeout": self.history_discovery_timeout,
            "history_task_timeout": self.history_task_timeout,
            "history_model_timeout": self.history_model_timeout,
            "history_summary_reserve": self.history_summary_reserve,
            "history_max_agents": self.history_max_agents,
            "history_diff_chars": self.history_diff_chars,
            "screen_wave_timeout": self.screen_wave_timeout,
            "screen_wave_model_calls": self.screen_wave_model_calls,
            "screen_tool_output_chars": self.screen_tool_output_chars,
            "screen_context_chars": self.screen_context_chars,
            "discover_context_tokens": self.discover_context_tokens,
            "discover_request_timeout": self.discover_request_timeout,
            "discover_search_max_file_bytes": self.discover_search_max_file_bytes,
            "discover_search_max_scan_files": self.discover_search_max_scan_files,
            "discover_notes_max": self.discover_notes_max,
            "discover_note_chars": self.discover_note_chars,
            "screen_wave_max_tasks": self.screen_wave_max_tasks,
            "screen_task_max_rounds": self.screen_task_max_rounds,
            "discover_recursion_limit": self.discover_recursion_limit,
            "audit_mode": self.audit_mode,
            "audit_timeout": self.audit_timeout,
            "audit_recursion_limit": self.audit_recursion_limit,
            "audit_max_agents": self.audit_max_agents,
            "audit_plan_batch_size": self.audit_plan_batch_size,
            "audit_max_total_tokens": self.audit_max_total_tokens,
            "audit_max_total_cost": self.audit_max_total_cost,
            "audit_model_concurrency": self.audit_model_concurrency,
            "validate_env_model": self.validate_env_model,
            "validate_env_gate_mode": self.validate_env_gate_mode,
            "validate_env_max_plan_calls": self.validate_env_max_plan_calls,
            "validate_env_max_diagnose_calls": self.validate_env_max_diagnose_calls,
            "validate_env_max_build_attempts": self.validate_env_max_build_attempts,
            "validate_env_max_plan_revisions": self.validate_env_max_plan_revisions,
            "validate_env_max_gate_revisions": self.validate_env_max_gate_revisions,
            "validate_env_llm_timeout": self.validate_env_llm_timeout,
            "validate_env_agent_max_rounds": self.validate_env_agent_max_rounds,
            "validate_env_agent_max_calls": self.validate_env_agent_max_calls,
            "validate_env_tool_output_chars": self.validate_env_tool_output_chars,
            "validate_env_context_chars": self.validate_env_context_chars,
            "validate_env_max_context_bytes": self.validate_env_max_context_bytes,
            "validate_env_max_context_files": self.validate_env_max_context_files,
            "validate_env_recursion_limit": self.validate_env_recursion_limit,
            "validate_env_base_image_allowlist": list(self.validate_env_base_image_allowlist),
            "validate_docker_bin": self.validate_docker_bin,
            "validate_docker_host": self.validate_docker_host,
            "validate_docker_pull": self.validate_docker_pull,
            "validate_docker_platform": self.validate_docker_platform,
            "validate_docker_build_timeout": self.validate_docker_build_timeout,
            "validate_docker_smoke_timeout": self.validate_docker_smoke_timeout,
            "validate_docker_memory": self.validate_docker_memory,
            "validate_docker_cpus": self.validate_docker_cpus,
            "validate_docker_pids": self.validate_docker_pids,
            "validate_docker_log_bytes": self.validate_docker_log_bytes,
            "validate_model": self.validate_model,
            "validate_llm_timeout": self.validate_llm_timeout,
            "validate_agent_max_rounds": self.validate_agent_max_rounds,
            "validate_agent_max_calls": self.validate_agent_max_calls,
            "validate_tool_output_chars": self.validate_tool_output_chars,
            "validate_command_timeout": self.validate_command_timeout,
            "validate_total_timeout": self.validate_total_timeout,
            "validate_max_total_tokens": self.validate_max_total_tokens,
            "validate_max_total_cost": self.validate_max_total_cost,
            "report_model": self.report_model,
            "report_language": self.report_language,
            "report_llm_timeout": self.report_llm_timeout,
            "report_total_timeout": self.report_total_timeout,
            "report_max_total_tokens": self.report_max_total_tokens,
            "report_max_total_cost": self.report_max_total_cost,
            "report_max_findings": self.report_max_findings,
            "planner_model": self.planner_model,
            "planner_max_calls": self.planner_max_calls,
            "planner_max_new_tasks": self.planner_max_new_tasks,
            "planner_max_files": self.planner_max_files,
            "planner_max_chars": self.planner_max_chars,
            "review_model": self.review_model,
            "review_max_calls": self.review_max_calls,
            "review_timeout": self.review_timeout,
            "review_stagnation_waves": self.review_stagnation_waves,
            "feature_max_results": self.feature_max_results,
            "feature_max_tasks": self.feature_max_tasks,
            "feature_query_timeout": self.feature_query_timeout,
            "feature_max_regex_chars": self.feature_max_regex_chars,
            "confirm_model": self.confirm_model,
            "confirm_timeout": self.confirm_timeout,
            "confirm_max_calls": self.confirm_max_calls,
            "confirm_max_tasks": self.confirm_max_tasks,
            "confirm_max_candidates": self.confirm_max_candidates,
            "confirm_max_same_file": self.confirm_max_same_file,
            "agent_max_rounds_per_invocation": self.agent_max_rounds_per_invocation,
            "documents_max_model_calls": self.documents_max_model_calls,
            "documents_discovery_max_model_calls": self.documents_discovery_max_model_calls,
            "documents_summary_max_model_calls": self.documents_summary_max_model_calls,
            "history_max_model_calls": self.history_max_model_calls,
            "history_discovery_max_model_calls": self.history_discovery_max_model_calls,
            "history_summary_max_model_calls": self.history_summary_max_model_calls,
            "patch_max_model_calls": self.patch_max_model_calls,
            "agent_hard_task_cap": self.agent_hard_task_cap,
            "agent_tool_result_tokens": self.agent_tool_result_tokens,
            "agent_keep_recent_results": self.agent_keep_recent_results,
            "agent_context_tokens": self.agent_context_tokens,
            "agent_compaction_trigger": self.agent_compaction_trigger,
            "agent_token_safety": self.agent_token_safety,
            "tools_fs_read_timeout": self.tools_fs_read_timeout,
            "tools_fs_search_timeout": self.tools_fs_search_timeout,
            "tools_git_timeout": self.tools_git_timeout,
            "tools_http_timeout": self.tools_http_timeout,
            "tools_http_max_bytes": self.tools_http_max_bytes,
            "documents_max_text_bytes": self.documents_max_text_bytes,
            "documents_max_pdf_bytes": self.documents_max_pdf_bytes,
            "documents_max_pdf_pages": self.documents_max_pdf_pages,
            "documents_max_docx_bytes": self.documents_max_docx_bytes,
            "documents_max_docx_blocks": self.documents_max_docx_blocks,
            "agent_cache_bytes": self.agent_cache_bytes,
            "agent_model_retries": self.agent_model_retries,
            "agent_json_repair_attempts": self.agent_json_repair_attempts,
            "agent_tool_retries": self.agent_tool_retries,
            "documents_agent_chunk_tokens": self.documents_agent_chunk_tokens,
            "documents_read_mode": self.documents_read_mode,
            "usage_price_table": str(self.usage_price_table) if self.usage_price_table else "",
        }


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def load_settings(env_file: Path | None = None) -> Settings:
    """Load environment variables, falling back to a local .env file."""
    file_values = _read_env_file(env_file or Path.cwd() / ".env")

    def value(name: str, default: str = "") -> str:
        return os.environ.get(name, file_values.get(name, default))

    def positive_int(name: str, default: int) -> int:
        raw = value(name, str(default)).strip() or str(default)
        parsed = int(raw)
        if parsed <= 0:
            raise ValueError(f"{name} must be greater than zero")
        return parsed

    def positive_float(name: str, default: float) -> float:
        raw = value(name, str(default)).strip() or str(default)
        parsed = float(raw)
        if parsed <= 0:
            raise ValueError(f"{name} must be greater than zero")
        return parsed

    def non_negative_int(name: str, default: int) -> int:
        raw = value(name, str(default)).strip() or str(default)
        parsed = int(raw)
        if parsed < 0:
            raise ValueError(f"{name} must be zero or greater")
        return parsed

    def non_negative_float(name: str, default: float) -> float:
        raw = value(name, str(default)).strip() or str(default)
        parsed = float(raw)
        if parsed < 0:
            raise ValueError(f"{name} must be zero or greater")
        return parsed

    def read_mode(name: str, default: str) -> str:
        raw = (value(name, default).strip().lower() or default)
        if raw not in {"auto", "agent", "map"}:
            raise ValueError(f"{name} must be one of auto, agent, map")
        return raw

    def read_audit_mode() -> str:
        raw = value("AUDIT_MODE", DEFAULT_AUDIT_MODE).strip().lower() or DEFAULT_AUDIT_MODE
        if raw not in AUDIT_MODES:
            raise ValueError(f"AUDIT_MODE must be one of {', '.join(AUDIT_MODES)}")
        return raw

    def choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
        raw = (value(name, default).strip().lower() or default)
        if raw not in allowed:
            raise ValueError(f"{name} must be one of {', '.join(allowed)}")
        return raw

    def csv_tuple(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
        raw = value(name, ",".join(default)).strip()
        items = tuple(item.strip() for item in raw.split(",") if item.strip())
        return items or default

    api_key = value("LLM_API_KEY").strip() or None
    screen_context_chars = positive_int(
        "DISCOVER_SCREEN_CONTEXT_CHARS", DEFAULT_SCREEN_CONTEXT_CHARS
    )
    discover_context_tokens = positive_int(
        "DISCOVER_CONTEXT_TOKENS", max(1, screen_context_chars // 4)
    )
    return Settings(
        api_key=api_key,
        base_url=value("LLM_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL,
        model=value("LLM_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL,
        cwe_archive_path=Path(
            value("CWE_ARCHIVE_PATH", str(DEFAULT_CWE_ARCHIVE_PATH)).strip()
            or str(DEFAULT_CWE_ARCHIVE_PATH)
        ).expanduser(),
        yasa_source_path=Path(
            value("YASA_SOURCE_PATH", str(DEFAULT_YASA_SOURCE_PATH)).strip()
            or str(DEFAULT_YASA_SOURCE_PATH)
        ).expanduser(),
        yasa_bin_path=Path(
            value("YASA_BIN_PATH", str(DEFAULT_YASA_BIN_PATH)).strip()
            or str(DEFAULT_YASA_BIN_PATH)
        ).expanduser(),
        yasa_init_timeout=positive_int("YASA_INIT_TIMEOUT", DEFAULT_YASA_INIT_TIMEOUT),
        yasa_status_timeout=positive_int("YASA_STATUS_TIMEOUT", DEFAULT_YASA_STATUS_TIMEOUT),
        yasa_mcp_timeout=positive_int("YASA_MCP_TIMEOUT", DEFAULT_YASA_MCP_TIMEOUT),
        documents_timeout=positive_int("DOCUMENTS_TIMEOUT", DEFAULT_DOCUMENTS_TIMEOUT),
        documents_model_timeout=positive_int(
            "DOCUMENTS_MODEL_TIMEOUT", DEFAULT_DOCUMENTS_MODEL_TIMEOUT
        ),
        documents_fetch_timeout=positive_int(
            "DOCUMENTS_FETCH_TIMEOUT", DEFAULT_DOCUMENTS_FETCH_TIMEOUT
        ),
        documents_chunk_chars=positive_int(
            "DOCUMENTS_CHUNK_CHARS", DEFAULT_DOCUMENTS_CHUNK_CHARS
        ),
        documents_context_chars=positive_int(
            "DOCUMENTS_CONTEXT_CHARS", DEFAULT_DOCUMENTS_CONTEXT_CHARS
        ),
        documents_summary_reserve=positive_int(
            "DOCUMENTS_SUMMARY_RESERVE", DEFAULT_DOCUMENTS_SUMMARY_RESERVE
        ),
        history_timeout=positive_int("SECURITY_HISTORY_TIMEOUT", DEFAULT_HISTORY_TIMEOUT),
        history_discovery_timeout=positive_int(
            "SECURITY_HISTORY_DISCOVERY_TIMEOUT", DEFAULT_HISTORY_DISCOVERY_TIMEOUT
        ),
        history_task_timeout=positive_int(
            "SECURITY_HISTORY_TASK_TIMEOUT", DEFAULT_HISTORY_TASK_TIMEOUT
        ),
        history_model_timeout=positive_int(
            "SECURITY_HISTORY_MODEL_TIMEOUT", DEFAULT_HISTORY_MODEL_TIMEOUT
        ),
        history_summary_reserve=positive_int(
            "SECURITY_HISTORY_SUMMARY_RESERVE", DEFAULT_HISTORY_SUMMARY_RESERVE
        ),
        history_max_agents=positive_int(
            "SECURITY_HISTORY_MAX_AGENTS", DEFAULT_HISTORY_MAX_AGENTS
        ),
        history_diff_chars=positive_int(
            "SECURITY_HISTORY_DIFF_CHARS", DEFAULT_HISTORY_DIFF_CHARS
        ),
        screen_wave_timeout=positive_int(
            "DISCOVER_SCREEN_WAVE_TIMEOUT", DEFAULT_SCREEN_WAVE_TIMEOUT
        ),
        screen_wave_model_calls=positive_int(
            "DISCOVER_SCREEN_WAVE_MODEL_CALLS", DEFAULT_SCREEN_WAVE_MODEL_CALLS
        ),
        screen_tool_output_chars=positive_int(
            "DISCOVER_SCREEN_TOOL_OUTPUT_CHARS", DEFAULT_SCREEN_TOOL_OUTPUT_CHARS
        ),
        screen_context_chars=screen_context_chars,
        discover_context_tokens=discover_context_tokens,
        discover_request_timeout=positive_int(
            "DISCOVER_REQUEST_TIMEOUT", DEFAULT_DISCOVER_REQUEST_TIMEOUT
        ),
        discover_search_max_file_bytes=positive_int(
            "DISCOVER_SEARCH_MAX_FILE_BYTES", DEFAULT_DISCOVER_SEARCH_MAX_FILE_BYTES
        ),
        discover_search_max_scan_files=positive_int(
            "DISCOVER_SEARCH_MAX_SCAN_FILES", DEFAULT_DISCOVER_SEARCH_MAX_SCAN_FILES
        ),
        discover_notes_max=positive_int("DISCOVER_NOTES_MAX", DEFAULT_DISCOVER_NOTES_MAX),
        discover_note_chars=positive_int("DISCOVER_NOTE_CHARS", DEFAULT_DISCOVER_NOTE_CHARS),
        screen_wave_max_tasks=positive_int(
            "DISCOVER_SCREEN_WAVE_MAX_TASKS", DEFAULT_SCREEN_WAVE_MAX_TASKS
        ),
        screen_task_max_rounds=positive_int(
            "DISCOVER_SCREEN_TASK_MAX_ROUNDS", DEFAULT_SCREEN_TASK_MAX_ROUNDS
        ),
        discover_recursion_limit=positive_int(
            "DISCOVER_RECURSION_LIMIT", DEFAULT_DISCOVER_RECURSION_LIMIT
        ),
        audit_mode=read_audit_mode(),
        audit_timeout=positive_int("AUDIT_TIMEOUT", DEFAULT_AUDIT_TIMEOUT),
        audit_recursion_limit=positive_int(
            "AUDIT_RECURSION_LIMIT", DEFAULT_AUDIT_RECURSION_LIMIT
        ),
        audit_max_agents=positive_int("AUDIT_MAX_AGENTS", DEFAULT_AUDIT_MAX_AGENTS),
        audit_plan_batch_size=positive_int(
            "AUDIT_PLAN_BATCH_SIZE", DEFAULT_AUDIT_PLAN_BATCH_SIZE
        ),
        audit_max_total_tokens=non_negative_int(
            "AUDIT_MAX_TOTAL_TOKENS", DEFAULT_AUDIT_MAX_TOTAL_TOKENS
        ),
        audit_max_total_cost=non_negative_float(
            "AUDIT_MAX_TOTAL_COST", DEFAULT_AUDIT_MAX_TOTAL_COST
        ),
        audit_model_concurrency=positive_int(
            "AUDIT_MODEL_CONCURRENCY", DEFAULT_AUDIT_MODEL_CONCURRENCY
        ),
        planner_model=value("DISCOVER_PLANNER_MODEL").strip(),
        planner_max_calls=positive_int(
            "DISCOVER_PLANNER_MAX_CALLS", DEFAULT_PLANNER_MAX_CALLS
        ),
        planner_max_new_tasks=positive_int(
            "DISCOVER_PLANNER_MAX_NEW_TASKS", DEFAULT_PLANNER_MAX_NEW_TASKS
        ),
        planner_max_files=positive_int(
            "DISCOVER_PLANNER_MAX_FILES", DEFAULT_PLANNER_MAX_FILES
        ),
        planner_max_chars=positive_int(
            "DISCOVER_PLANNER_MAX_CHARS", DEFAULT_PLANNER_MAX_CHARS
        ),
        review_model=value("DISCOVER_REVIEW_MODEL").strip(),
        review_max_calls=positive_int(
            "DISCOVER_REVIEW_MAX_CALLS", DEFAULT_REVIEW_MAX_CALLS
        ),
        review_timeout=positive_int(
            "DISCOVER_REVIEW_TIMEOUT", DEFAULT_REVIEW_TIMEOUT
        ),
        review_stagnation_waves=positive_int(
            "DISCOVER_REVIEW_STAGNATION_WAVES", DEFAULT_REVIEW_STAGNATION_WAVES
        ),
        feature_max_results=positive_int(
            "DISCOVER_FEATURE_MAX_RESULTS", DEFAULT_FEATURE_MAX_RESULTS
        ),
        feature_max_tasks=positive_int(
            "DISCOVER_FEATURE_MAX_TASKS", DEFAULT_FEATURE_MAX_TASKS
        ),
        feature_query_timeout=positive_int(
            "DISCOVER_FEATURE_QUERY_TIMEOUT", DEFAULT_FEATURE_QUERY_TIMEOUT
        ),
        feature_max_regex_chars=positive_int(
            "DISCOVER_FEATURE_MAX_REGEX_CHARS", DEFAULT_FEATURE_MAX_REGEX_CHARS
        ),
        confirm_model=value("DISCOVER_CONFIRM_MODEL").strip(),
        confirm_timeout=positive_int(
            "DISCOVER_CONFIRM_TIMEOUT", DEFAULT_CONFIRM_TIMEOUT
        ),
        confirm_max_calls=positive_int(
            "DISCOVER_CONFIRM_MAX_CALLS", DEFAULT_CONFIRM_MAX_CALLS
        ),
        confirm_max_tasks=positive_int(
            "DISCOVER_CONFIRM_MAX_TASKS", DEFAULT_CONFIRM_MAX_TASKS
        ),
        confirm_max_candidates=positive_int(
            "DISCOVER_CONFIRM_MAX_CANDIDATES", DEFAULT_CONFIRM_MAX_CANDIDATES
        ),
        confirm_max_same_file=positive_int(
            "DISCOVER_CONFIRM_MAX_SAME_FILE", DEFAULT_CONFIRM_MAX_SAME_FILE
        ),
        agent_max_rounds_per_invocation=positive_int(
            "AGENT_MAX_ROUNDS_PER_CALL", DEFAULT_AGENT_MAX_ROUNDS_PER_INVOCATION
        ),
        documents_max_model_calls=positive_int(
            "DOCUMENTS_MAX_MODEL_CALLS", DEFAULT_DOCUMENTS_MAX_MODEL_CALLS
        ),
        documents_discovery_max_model_calls=positive_int(
            "DOCUMENTS_DISCOVERY_MAX_MODEL_CALLS", DEFAULT_DOCUMENTS_DISCOVERY_MAX_MODEL_CALLS
        ),
        documents_summary_max_model_calls=positive_int(
            "DOCUMENTS_SUMMARY_MAX_MODEL_CALLS", DEFAULT_DOCUMENTS_SUMMARY_MAX_MODEL_CALLS
        ),
        history_max_model_calls=positive_int(
            "SECURITY_HISTORY_MAX_MODEL_CALLS", DEFAULT_HISTORY_MAX_MODEL_CALLS
        ),
        history_discovery_max_model_calls=positive_int(
            "SECURITY_HISTORY_DISCOVERY_MAX_MODEL_CALLS",
            DEFAULT_HISTORY_DISCOVERY_MAX_MODEL_CALLS,
        ),
        history_summary_max_model_calls=positive_int(
            "SECURITY_HISTORY_SUMMARY_MAX_MODEL_CALLS", DEFAULT_HISTORY_SUMMARY_MAX_MODEL_CALLS
        ),
        patch_max_model_calls=positive_int(
            "SECURITY_HISTORY_PATCH_MAX_MODEL_CALLS", DEFAULT_PATCH_MAX_MODEL_CALLS
        ),
        agent_hard_task_cap=positive_int("AGENT_HARD_TASK_CAP", DEFAULT_AGENT_HARD_TASK_CAP),
        agent_tool_result_tokens=positive_int(
            "AGENT_TOOL_RESULT_TOKENS", DEFAULT_AGENT_TOOL_RESULT_TOKENS
        ),
        agent_keep_recent_results=positive_int(
            "AGENT_KEEP_RECENT_RESULTS", DEFAULT_AGENT_KEEP_RECENT_RESULTS
        ),
        agent_context_tokens=positive_int("AGENT_CONTEXT_TOKENS", DEFAULT_AGENT_CONTEXT_TOKENS),
        agent_compaction_trigger=positive_float(
            "AGENT_COMPACTION_TRIGGER", DEFAULT_AGENT_COMPACTION_TRIGGER
        ),
        agent_token_safety=positive_float("AGENT_TOKEN_SAFETY", DEFAULT_AGENT_TOKEN_SAFETY),
        tools_fs_read_timeout=positive_int(
            "TOOLS_FS_READ_TIMEOUT", DEFAULT_TOOLS_FS_READ_TIMEOUT
        ),
        tools_fs_search_timeout=positive_int(
            "TOOLS_FS_SEARCH_TIMEOUT", DEFAULT_TOOLS_FS_SEARCH_TIMEOUT
        ),
        tools_git_timeout=positive_int("TOOLS_GIT_TIMEOUT", DEFAULT_TOOLS_GIT_TIMEOUT),
        tools_http_timeout=positive_int("TOOLS_HTTP_TIMEOUT", DEFAULT_TOOLS_HTTP_TIMEOUT),
        tools_http_max_bytes=positive_int(
            "TOOLS_HTTP_MAX_BYTES", DEFAULT_TOOLS_HTTP_MAX_BYTES
        ),
        documents_max_text_bytes=positive_int(
            "DOCUMENTS_MAX_TEXT_BYTES", DEFAULT_DOCUMENTS_MAX_TEXT_BYTES
        ),
        documents_max_pdf_bytes=positive_int(
            "DOCUMENTS_MAX_PDF_BYTES", DEFAULT_DOCUMENTS_MAX_PDF_BYTES
        ),
        documents_max_pdf_pages=positive_int(
            "DOCUMENTS_MAX_PDF_PAGES", DEFAULT_DOCUMENTS_MAX_PDF_PAGES
        ),
        documents_max_docx_bytes=positive_int(
            "DOCUMENTS_MAX_DOCX_BYTES", DEFAULT_DOCUMENTS_MAX_DOCX_BYTES
        ),
        documents_max_docx_blocks=positive_int(
            "DOCUMENTS_MAX_DOCX_BLOCKS", DEFAULT_DOCUMENTS_MAX_DOCX_BLOCKS
        ),
        agent_cache_bytes=positive_int("AGENT_CACHE_BYTES", DEFAULT_AGENT_CACHE_BYTES),
        agent_model_retries=positive_int("AGENT_MODEL_RETRIES", DEFAULT_AGENT_MODEL_RETRIES),
        agent_json_repair_attempts=positive_int(
            "AGENT_JSON_REPAIR_ATTEMPTS", DEFAULT_AGENT_JSON_REPAIR_ATTEMPTS
        ),
        agent_tool_retries=positive_int("AGENT_TOOL_RETRIES", DEFAULT_AGENT_TOOL_RETRIES),
        documents_agent_chunk_tokens=positive_int(
            "DOCUMENTS_AGENT_CHUNK_TOKENS", DEFAULT_DOCUMENTS_AGENT_CHUNK_TOKENS
        ),
        documents_read_mode=read_mode("DOCUMENTS_READ_MODE", DEFAULT_DOCUMENTS_READ_MODE),
        validate_env_model=value("VALIDATE_ENV_MODEL").strip(),
        validate_env_gate_mode=choice(
            "VALIDATE_ENV_GATE_MODE",
            DEFAULT_VALIDATE_ENV_GATE_MODE,
            VALIDATE_ENV_GATE_MODES,
        ),
        validate_env_max_plan_calls=positive_int(
            "VALIDATE_ENV_MAX_PLAN_CALLS", DEFAULT_VALIDATE_ENV_MAX_PLAN_CALLS
        ),
        validate_env_max_diagnose_calls=positive_int(
            "VALIDATE_ENV_MAX_DIAGNOSE_CALLS", DEFAULT_VALIDATE_ENV_MAX_DIAGNOSE_CALLS
        ),
        validate_env_max_build_attempts=positive_int(
            "VALIDATE_ENV_MAX_BUILD_ATTEMPTS", DEFAULT_VALIDATE_ENV_MAX_BUILD_ATTEMPTS
        ),
        validate_env_max_plan_revisions=positive_int(
            "VALIDATE_ENV_MAX_PLAN_REVISIONS", DEFAULT_VALIDATE_ENV_MAX_PLAN_REVISIONS
        ),
        validate_env_max_gate_revisions=positive_int(
            "VALIDATE_ENV_MAX_GATE_REVISIONS", DEFAULT_VALIDATE_ENV_MAX_GATE_REVISIONS
        ),
        validate_env_llm_timeout=positive_int(
            "VALIDATE_ENV_LLM_TIMEOUT", DEFAULT_VALIDATE_ENV_LLM_TIMEOUT
        ),
        validate_env_agent_max_rounds=positive_int(
            "VALIDATE_ENV_AGENT_MAX_ROUNDS", DEFAULT_VALIDATE_ENV_AGENT_MAX_ROUNDS
        ),
        validate_env_agent_max_calls=positive_int(
            "VALIDATE_ENV_AGENT_MAX_CALLS", DEFAULT_VALIDATE_ENV_AGENT_MAX_CALLS
        ),
        validate_env_tool_output_chars=positive_int(
            "VALIDATE_ENV_TOOL_OUTPUT_CHARS", DEFAULT_VALIDATE_ENV_TOOL_OUTPUT_CHARS
        ),
        validate_env_context_chars=positive_int(
            "VALIDATE_ENV_CONTEXT_CHARS", DEFAULT_VALIDATE_ENV_CONTEXT_CHARS
        ),
        validate_env_max_context_bytes=positive_int(
            "VALIDATE_ENV_MAX_CONTEXT_BYTES", DEFAULT_VALIDATE_ENV_MAX_CONTEXT_BYTES
        ),
        validate_env_max_context_files=positive_int(
            "VALIDATE_ENV_MAX_CONTEXT_FILES", DEFAULT_VALIDATE_ENV_MAX_CONTEXT_FILES
        ),
        validate_env_recursion_limit=positive_int(
            "VALIDATE_ENV_RECURSION_LIMIT", DEFAULT_VALIDATE_ENV_RECURSION_LIMIT
        ),
        validate_env_base_image_allowlist=csv_tuple(
            "VALIDATE_ENV_BASE_IMAGE_ALLOWLIST",
            DEFAULT_VALIDATE_ENV_BASE_IMAGE_ALLOWLIST,
        ),
        validate_docker_bin=value("VALIDATE_DOCKER_BIN", DEFAULT_VALIDATE_DOCKER_BIN).strip()
        or DEFAULT_VALIDATE_DOCKER_BIN,
        validate_docker_host=value("VALIDATE_DOCKER_HOST").strip(),
        validate_docker_pull=choice(
            "VALIDATE_DOCKER_PULL",
            DEFAULT_VALIDATE_DOCKER_PULL,
            ("always", "missing", "never"),
        ),
        validate_docker_platform=value("VALIDATE_DOCKER_PLATFORM").strip(),
        validate_docker_build_timeout=positive_int(
            "VALIDATE_DOCKER_BUILD_TIMEOUT", DEFAULT_VALIDATE_DOCKER_BUILD_TIMEOUT
        ),
        validate_docker_smoke_timeout=positive_int(
            "VALIDATE_DOCKER_SMOKE_TIMEOUT", DEFAULT_VALIDATE_DOCKER_SMOKE_TIMEOUT
        ),
        validate_docker_memory=value(
            "VALIDATE_DOCKER_MEMORY", DEFAULT_VALIDATE_DOCKER_MEMORY
        ).strip()
        or DEFAULT_VALIDATE_DOCKER_MEMORY,
        validate_docker_cpus=positive_float(
            "VALIDATE_DOCKER_CPUS", DEFAULT_VALIDATE_DOCKER_CPUS
        ),
        validate_docker_pids=positive_int(
            "VALIDATE_DOCKER_PIDS", DEFAULT_VALIDATE_DOCKER_PIDS
        ),
        validate_docker_log_bytes=positive_int(
            "VALIDATE_DOCKER_LOG_BYTES", DEFAULT_VALIDATE_DOCKER_LOG_BYTES
        ),
        validate_model=value("VALIDATE_MODEL").strip(),
        validate_llm_timeout=positive_int(
            "VALIDATE_LLM_TIMEOUT", DEFAULT_VALIDATE_LLM_TIMEOUT
        ),
        validate_agent_max_rounds=positive_int(
            "VALIDATE_AGENT_MAX_ROUNDS", DEFAULT_VALIDATE_AGENT_MAX_ROUNDS
        ),
        validate_agent_max_calls=positive_int(
            "VALIDATE_AGENT_MAX_CALLS", DEFAULT_VALIDATE_AGENT_MAX_CALLS
        ),
        validate_tool_output_chars=positive_int(
            "VALIDATE_TOOL_OUTPUT_CHARS", DEFAULT_VALIDATE_TOOL_OUTPUT_CHARS
        ),
        validate_command_timeout=positive_int(
            "VALIDATE_COMMAND_TIMEOUT", DEFAULT_VALIDATE_COMMAND_TIMEOUT
        ),
        validate_total_timeout=positive_int(
            "VALIDATE_TOTAL_TIMEOUT", DEFAULT_VALIDATE_TOTAL_TIMEOUT
        ),
        validate_max_total_tokens=non_negative_int(
            "VALIDATE_MAX_TOTAL_TOKENS", DEFAULT_VALIDATE_MAX_TOTAL_TOKENS
        ),
        validate_max_total_cost=non_negative_float(
            "VALIDATE_MAX_TOTAL_COST", DEFAULT_VALIDATE_MAX_TOTAL_COST
        ),
        report_model=value("REPORT_MODEL").strip(),
        report_language=value("REPORT_LANGUAGE").strip() or DEFAULT_REPORT_LANGUAGE,
        report_llm_timeout=positive_int(
            "REPORT_LLM_TIMEOUT", DEFAULT_REPORT_LLM_TIMEOUT
        ),
        report_total_timeout=positive_int(
            "REPORT_TOTAL_TIMEOUT", DEFAULT_REPORT_TOTAL_TIMEOUT
        ),
        report_max_total_tokens=non_negative_int(
            "REPORT_MAX_TOTAL_TOKENS", DEFAULT_REPORT_MAX_TOTAL_TOKENS
        ),
        report_max_total_cost=non_negative_float(
            "REPORT_MAX_TOTAL_COST", DEFAULT_REPORT_MAX_TOTAL_COST
        ),
        report_max_findings=positive_int(
            "REPORT_MAX_FINDINGS", DEFAULT_REPORT_MAX_FINDINGS
        ),
        usage_price_table=(
            Path(value("USAGE_PRICE_TABLE").strip()).expanduser()
            if value("USAGE_PRICE_TABLE").strip()
            else None
        ),
    )
