"""Unit tests for utils.exceptions."""
from utils.exceptions import (
    CaptureError,
    CipherError,
    LiveCaptureNotImplementedError,
    ParsingError,
)


def test_cipher_error_is_an_exception() -> None:
    assert issubclass(CipherError, Exception)


def test_capture_error_is_a_cipher_error() -> None:
    assert issubclass(CaptureError, CipherError)


def test_parsing_error_is_a_cipher_error() -> None:
    assert issubclass(ParsingError, CipherError)


def test_live_capture_not_implemented_is_a_capture_error() -> None:
    """This is the specific hierarchy relationship the pipeline (a
    future step) will rely on to catch live-capture failures as a
    subset of capture failures generally."""
    assert issubclass(LiveCaptureNotImplementedError, CaptureError)
    assert issubclass(LiveCaptureNotImplementedError, CipherError)


def test_exceptions_carry_a_message() -> None:
    err = CaptureError("something went wrong")
    assert str(err) == "something went wrong"