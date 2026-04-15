"""Logging utilities for NightWatch."""

import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.logging import RichHandler
from rich.console import Console

LOG_DIR = Path.home() / "NightWatch" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class NightWatchLogger:
    """Structured logger with file + console output."""

    def __init__(self, name: str = "nightwatch", log_file: str = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # Console handler with Rich
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
        )
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_formatter)

        # File handler
        log_name = log_file or f"nightwatch_{datetime.now().strftime('%Y%m%d')}.log"
        file_path = LOG_DIR / log_name
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self.logger.critical(msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        self.logger.exception(msg, *args, **kwargs)


# Global logger instance
log = NightWatchLogger()


def get_logger(name: str = "nightwatch") -> NightWatchLogger:
    return NightWatchLogger(name)
