"""
CyberGuard Secure Application Logger.

Provides thread-safe, sanitized application logging to logs/cyberguard.log.
Enforces strict redaction filters to ensure passwords, hashes, tokens,
and authentication secrets are never recorded in plaintext log files.
"""

import logging
import re
from pathlib import Path
from typing import Optional

from config import DEFAULT_LOG_FILE, LOGS_DIR

# Sensitive keyword pattern to prevent accidental logging of credentials
REDACTION_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|private_key|auth_token)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)


class SensitiveDataFilter(logging.Filter):
    """
    Log filter that intercepts and masks sensitive data patterns such as passwords
    and API tokens before they can be written to disk or terminal streams.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = REDACTION_PATTERN.sub(r"\1=***REDACTED***", record.msg)
        if record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    sanitized_args.append(REDACTION_PATTERN.sub(r"\1=***REDACTED***", arg))
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        return True


def setup_logging(
    log_file: Optional[Path] = None,
    level: int = logging.INFO,
    enable_console: bool = False,
) -> None:
    """
    Configures root logging with security redaction filters and file handlers.
    
    :param log_file: Custom path to log file, defaults to logs/cyberguard.log
    :param level: Logging severity level (e.g., logging.INFO, logging.DEBUG)
    :param enable_console: If True, also outputs log messages to console
    """
    target_log_file = log_file or DEFAULT_LOG_FILE
    target_dir = target_log_file.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger("cyberguard")
    root_logger.setLevel(level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if root_logger.handlers:
        return

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    redaction_filter = SensitiveDataFilter()

    # File Handler
    try:
        file_handler = logging.FileHandler(str(target_log_file), encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(redaction_filter)
        root_logger.addHandler(file_handler)
    except (OSError, IOError) as exc:
        logging.basicConfig(level=level)
        root_logger.warning("Could not initialize file log handler at %s: %s", target_log_file, exc)

    # Console Handler (optional)
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(redaction_filter)
        root_logger.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a scoped logger for a specific module under the cyberguard namespace.
    
    :param name: Module or component name
    :return: Configured logging.Logger instance
    """
    if not logging.getLogger("cyberguard").handlers:
        setup_logging()
    return logging.getLogger(f"cyberguard.{name}")
