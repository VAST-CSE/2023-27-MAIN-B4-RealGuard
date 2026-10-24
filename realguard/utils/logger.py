"""
utils/logger.py

Centralized logger for RealGuard.

Why this exists:
Every module (capture, detection, scoring, response) needs to log what it's doing —
both for debugging during development, and because a real security product must have
an audit trail (who/what triggered a block, when a model was retrained, etc).

Rather than each module calling `print()` or creating its own logger config,
they all import `get_logger(__name__)` from here. This guarantees consistent
timestamp format, consistent log file location, and one place to change the
logging level for the whole system (e.g. flip to DEBUG when troubleshooting).
"""

import logging
import os
import yaml

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "settings.yaml")


def _load_logging_config():
    with open(_CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
    return config.get("logging", {})


def get_logger(name: str) -> logging.Logger:
    """
    Returns a configured logger instance for the given module name.
    Usage: logger = get_logger(__name__)
    """
    cfg = _load_logging_config()
    log_file = cfg.get("log_file", "logs/realguard.log")
    level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    if not logger.handlers:  # prevent duplicate handlers if called multiple times
        logger.setLevel(level)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        )

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger
