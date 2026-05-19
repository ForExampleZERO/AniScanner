"""
scanner/logging_config.py  (v5.0)
Centralised logging setup.

Call setup_logging() once at startup (app.py).
Supports console + optional file logging via LOG_FILE env var.
"""

import logging
import logging.handlers
import os
import sys


def setup_logging(
    level:    str = "INFO",
    log_file: str | None = None,
) -> None:
    """
    Configure root logger.

    Args:
        level:    Log level string (DEBUG / INFO / WARNING / ERROR)
        log_file: Optional path for rotating file log
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter(
        fmt     = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # File handler (optional)
    file_path = log_file or os.environ.get("ANISCANNER_LOG_FILE")
    if file_path:
        try:
            fh = logging.handlers.RotatingFileHandler(
                file_path,
                maxBytes   = 10 * 1024 * 1024,   # 10 MB
                backupCount = 5,
                encoding   = "utf-8",
            )
            fh.setFormatter(fmt)
            root.addHandler(fh)
            root.info("File logging enabled → %s", file_path)
        except OSError as exc:
            root.warning("Could not open log file %s: %s", file_path, exc)

    # Silence noisy third-party loggers
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
