"""Unit tests for models.entropy_metrics.EntropyMetrics."""
import pytest

from models.entropy_metrics import EntropyMetrics


def test_valid_entropy_metrics() -> None:
    em = EntropyMetrics(shannon_entropy=7.99, sample_size=1024)
    assert em.shannon_entropy == 7.99


@pytest.mark.parametrize("value", [-0.1, 8.1, -5.0, 100.0])
def test_rejects_out_of_range_entropy(value: float) -> None:
    with pytest.raises(ValueError, match="shannon_entropy"):
        EntropyMetrics(shannon_entropy=value, sample_size=100)


def test_accepts_boundary_entropy_values() -> None:
    assert EntropyMetrics(shannon_entropy=0.0, sample_size=1).shannon_entropy == 0.0
    assert EntropyMetrics(shannon_entropy=8.0, sample_size=1).shannon_entropy == 8.0


def test_rejects_non_positive_sample_size() -> None:
    with pytest.raises(ValueError, match="sample_size"):
        EntropyMetrics(shannon_entropy=4.0, sample_size=0)


def test_round_trip_serialization() -> None:
    em1 = EntropyMetrics(shannon_entropy=6.5, sample_size=256)
    em2 = EntropyMetrics.from_dict(em1.to_dict())
    assert em1 == em2