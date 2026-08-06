"""Unit tests for utils.logging_setup."""
import logging

from config.settings import Settings
from utils.logging_setup import configure_logging


def test_configure_logging_creates_log_directory(tmp_path) -> None:
    settings = Settings(log_dir=tmp_path / "logs")
    configure_logging(settings)
    assert (tmp_path / "logs").exists()


def test_configure_logging_attaches_handlers(tmp_path) -> None:
    settings = Settings(log_dir=tmp_path / "logs")
    configure_logging(settings)
    root_logger = logging.getLogger()
    assert len(root_logger.handlers) == 2  # console + rotating file


def test_configure_logging_is_idempotent(tmp_path) -> None:
    """Calling it twice must not accumulate duplicate handlers."""
    settings = Settings(log_dir=tmp_path / "logs")
    configure_logging(settings)
    configure_logging(settings)
    root_logger = logging.getLogger()
    assert len(root_logger.handlers) == 2


def test_configure_logging_respects_log_level(tmp_path) -> None:
    settings = Settings(log_dir=tmp_path / "logs", log_level="DEBUG")
    configure_logging(settings)
    assert logging.getLogger().level == logging.DEBUG
