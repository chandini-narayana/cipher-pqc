"""Unit tests for capture.base.CaptureSource."""
import pytest

from capture.base import CaptureSource


def test_cannot_instantiate_abstract_base_directly() -> None:
    with pytest.raises(TypeError):
        CaptureSource()  # type: ignore[abstract]


def test_concrete_subclass_without_read_packets_cannot_instantiate() -> None:
    class Incomplete(CaptureSource):
        pass

    with pytest.raises(TypeError):
        Incomplete()  # type: ignore[abstract]


def test_concrete_subclass_with_read_packets_can_instantiate() -> None:
    class Complete(CaptureSource):
        def read_packets(self):
            return iter([])

    instance = Complete()
    assert list(instance.read_packets()) == []