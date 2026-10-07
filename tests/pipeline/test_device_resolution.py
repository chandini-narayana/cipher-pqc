"""Tests for pipeline.device_resolution — protected-device attribution.

Pure-function tests: no capture, no pipeline, no hardware, no network. The
frozen rule under test is, in order:

    src protected, dst not   -> src
    src not protected, dst   -> dst
    both protected           -> src
    neither protected        -> None
"""
from __future__ import annotations

import pytest

from pipeline.device_resolution import (
    InvalidProtectedScopeError,
    ProtectedScope,
    parse_protected_networks,
)

LAB = "192.168.50.0/24"
PI = "192.168.50.1"
CLIENT = "192.168.50.24"
OTHER_CLIENT = "192.168.50.77"
REMOTE = "93.184.216.34"


def _scope(networks=(LAB,), excluded=(PI,)) -> ProtectedScope:
    return ProtectedScope(networks, excluded_addresses=excluded)


# --- the frozen rule ------------------------------------------------------


def test_protected_to_internet_resolves_to_the_protected_source() -> None:
    """Outbound: unchanged from CIPHER's historic behaviour."""
    assert _scope().resolve(CLIENT, REMOTE) == CLIENT


def test_internet_to_protected_resolves_to_the_protected_destination() -> None:
    """Inbound: the fix. The remote server is a peer, not a device."""
    assert _scope().resolve(REMOTE, CLIENT) == CLIENT


def test_protected_to_protected_resolves_to_the_source() -> None:
    """Lab-to-lab: the sender is the actor, and one deterministic answer per
    packet is required."""
    assert _scope().resolve(CLIENT, OTHER_CLIENT) == CLIENT


def test_neither_protected_resolves_to_nothing() -> None:
    assert _scope().resolve(REMOTE, "8.8.8.8") is None


# --- the appliance itself is never a protected device ---------------------


def test_the_excluded_self_address_is_not_protected() -> None:
    """The Pi's own address is inside the protected /24, so a plain membership
    test would make the appliance a device of itself."""
    assert _scope().is_protected(PI) is False


def test_pi_to_protected_resolves_to_the_protected_destination() -> None:
    assert _scope().resolve(PI, CLIENT) == CLIENT


def test_protected_to_pi_resolves_to_the_protected_source() -> None:
    assert _scope().resolve(CLIENT, PI) == CLIENT


def test_internet_to_pi_resolves_to_nothing() -> None:
    assert _scope().resolve(REMOTE, PI) is None


def test_pi_to_internet_resolves_to_nothing() -> None:
    assert _scope().resolve(PI, REMOTE) is None


def test_pi_to_pi_resolves_to_nothing() -> None:
    assert _scope().resolve(PI, PI) is None


def test_without_an_exclusion_the_pi_address_would_be_protected() -> None:
    """Documents exactly what the exclusion is doing, so its removal would be
    an obvious test failure rather than a silent regression."""
    assert ProtectedScope([LAB]).is_protected(PI) is True
    assert _scope().is_protected(PI) is False


def test_several_excluded_addresses_are_all_honoured() -> None:
    scope = ProtectedScope([LAB], excluded_addresses=[PI, OTHER_CLIENT])
    assert scope.is_protected(PI) is False
    assert scope.is_protected(OTHER_CLIENT) is False
    assert scope.is_protected(CLIENT) is True


def test_an_unparseable_excluded_address_is_ignored_not_fatal() -> None:
    """Self-discovery is best-effort, so a junk entry means one fewer exclusion
    rather than a startup failure."""
    scope = ProtectedScope([LAB], excluded_addresses=["not-an-ip", "", None, PI])
    assert scope.is_protected(PI) is False
    assert scope.is_protected(CLIENT) is True


def test_a_non_ipv4_excluded_address_is_ignored() -> None:
    scope = ProtectedScope([LAB], excluded_addresses=["2001:db8::1", PI])
    assert scope.excluded_addresses == (PI,)


# --- membership -----------------------------------------------------------


def test_an_in_subnet_address_is_protected() -> None:
    assert _scope().is_protected(CLIENT) is True


def test_an_out_of_subnet_address_is_not_protected() -> None:
    assert _scope().is_protected(REMOTE) is False


def test_an_adjacent_subnet_is_not_protected() -> None:
    assert _scope().is_protected("192.168.51.24") is False


def test_the_network_and_broadcast_addresses_of_the_scope_are_not_protected() -> None:
    """Both are inside the CIDR but neither is a host, so neither may ever
    become a device identity (or, at QRS >= 7, an isolation target)."""
    assert _scope().is_protected("192.168.50.0") is False
    assert _scope().is_protected("192.168.50.255") is False


def test_pi_to_subnet_broadcast_resolves_to_nothing() -> None:
    """Regression: the excluded Pi sending a subnet-directed broadcast used to
    make 192.168.50.255 the device."""
    assert _scope().resolve(PI, "192.168.50.255") is None
    assert _scope().resolve(PI, "192.168.50.0") is None


def test_remote_to_subnet_broadcast_resolves_to_nothing() -> None:
    assert _scope().resolve(REMOTE, "192.168.50.255") is None


def test_hosts_at_the_edges_of_the_scope_are_still_protected() -> None:
    assert _scope().is_protected("192.168.50.2") is True
    assert _scope().is_protected("192.168.50.254") is True


def test_a_broadcast_of_one_network_is_refused_even_if_another_network_contains_it() -> None:
    scope = ProtectedScope(["10.0.0.0/24", "10.0.0.0/16"])
    assert scope.is_protected("10.0.0.255") is False
    assert scope.is_protected("10.0.1.255") is True  # a host of the /16 only


def test_slash_31_and_slash_32_networks_have_no_reserved_addresses() -> None:
    assert ProtectedScope(["10.9.9.0/31"]).is_protected("10.9.9.0") is True
    assert ProtectedScope(["10.9.9.0/31"]).is_protected("10.9.9.1") is True
    assert ProtectedScope(["10.9.9.9/32"]).is_protected("10.9.9.9") is True


# --- broadcast and multicast ---------------------------------------------


def test_a_limited_broadcast_destination_is_not_protected() -> None:
    assert _scope().is_protected("255.255.255.255") is False


def test_a_protected_client_broadcasting_still_attributes_to_the_client() -> None:
    assert _scope().resolve(CLIENT, "255.255.255.255") == CLIENT
    assert _scope().resolve(CLIENT, "192.168.50.255") == CLIENT


def test_a_remote_source_to_a_broadcast_destination_resolves_to_nothing() -> None:
    assert _scope().resolve(REMOTE, "255.255.255.255") is None


def test_multicast_is_not_protected() -> None:
    assert _scope().is_protected("224.0.0.251") is False
    assert _scope().resolve(REMOTE, "224.0.0.251") is None


def test_a_protected_client_sending_multicast_attributes_to_the_client() -> None:
    assert _scope().resolve(CLIENT, "224.0.0.251") == CLIENT


# --- malformed and unsupported addresses ---------------------------------


@pytest.mark.parametrize(
    "value", ["", "   ", "not-an-ip", "192.168.50", "192.168.50.999", "192.168.50.0/24", None, 42]
)
def test_a_malformed_address_is_never_protected_and_never_raises(value) -> None:
    assert _scope().is_protected(value) is False


def test_resolution_with_two_malformed_addresses_returns_none() -> None:
    assert _scope().resolve("not-an-ip", "also-not-an-ip") is None


def test_a_malformed_source_with_a_protected_destination_still_resolves() -> None:
    """Fails safe in the useful direction: one unusable field does not discard
    a packet that clearly concerns a protected device."""
    assert _scope().resolve("not-an-ip", CLIENT) == CLIENT


# --- IPv4 only ------------------------------------------------------------


def test_an_ipv6_address_is_never_protected() -> None:
    assert _scope().is_protected("2001:db8::1") is False


def test_ipv6_endpoints_resolve_to_nothing() -> None:
    assert _scope().resolve("2001:db8::1", "2001:db8::2") is None


def test_an_ipv6_network_is_refused_at_construction() -> None:
    with pytest.raises(InvalidProtectedScopeError) as excinfo:
        ProtectedScope(["2001:db8::/32"])
    assert "IPv4-only" in str(excinfo.value)


# --- multiple protected networks -----------------------------------------


def test_several_protected_networks_are_all_honoured() -> None:
    scope = ProtectedScope([LAB, "10.10.0.0/16"])

    assert scope.resolve(CLIENT, REMOTE) == CLIENT
    assert scope.resolve(REMOTE, "10.10.4.5") == "10.10.4.5"
    assert scope.resolve(REMOTE, "172.16.0.1") is None


def test_traffic_between_two_protected_networks_resolves_to_the_source() -> None:
    scope = ProtectedScope([LAB, "10.10.0.0/16"])
    assert scope.resolve("10.10.4.5", CLIENT) == "10.10.4.5"


def test_a_single_host_network_is_accepted() -> None:
    scope = ProtectedScope(["192.168.50.24/32"])
    assert scope.resolve(REMOTE, CLIENT) == CLIENT
    assert scope.resolve(REMOTE, OTHER_CLIENT) is None


# --- construction and parsing --------------------------------------------


def test_a_host_bit_is_tolerated_and_normalised() -> None:
    """strict=False, so 192.168.50.24/24 is read as the /24 it describes."""
    scope = ProtectedScope(["192.168.50.24/24"])
    assert scope.networks == ("192.168.50.0/24",)


def test_a_bare_address_is_read_as_a_single_host() -> None:
    assert ProtectedScope([CLIENT]).networks == ("192.168.50.24/32",)


def test_an_empty_network_list_is_refused() -> None:
    with pytest.raises(InvalidProtectedScopeError):
        ProtectedScope([])


@pytest.mark.parametrize("value", ["nonsense", "192.168.50.0/33", "", "   ", "10.0.0.0/-1"])
def test_an_invalid_network_is_refused_at_construction(value) -> None:
    with pytest.raises(InvalidProtectedScopeError):
        ProtectedScope([value])


def test_parse_accepts_a_comma_separated_list() -> None:
    assert parse_protected_networks("192.168.50.0/24, 10.10.0.0/16") == (
        "192.168.50.0/24",
        "10.10.0.0/16",
    )


def test_parse_treats_unset_as_no_scope() -> None:
    """The opt-in default: no scope means legacy src_ip identity."""
    assert parse_protected_networks(None) == ()
    assert parse_protected_networks("") == ()
    assert parse_protected_networks("   ") == ()
    assert parse_protected_networks(",, ,") == ()


def test_parse_rejects_an_invalid_entry() -> None:
    with pytest.raises(InvalidProtectedScopeError):
        parse_protected_networks("192.168.50.0/24,nonsense")


def test_the_networks_are_reported_for_logging() -> None:
    assert _scope().networks == ("192.168.50.0/24",)


# --- the module stays pure and dependency-free ---------------------------


def test_the_module_imports_only_the_standard_library() -> None:
    """Subnet policy must not drag capture, ML, hardware, dashboard or
    enforcement into the identity decision."""
    import ast
    import inspect

    import pipeline.device_resolution as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in (
        "capture",
        "ml",
        "hardware",
        "dashboard",
        "enforcement",
        "reports",
        "risk",
        "fusion",
        "entropy",
        "scapy",
    ):
        assert forbidden not in imported
    assert "ipaddress" in imported


def test_resolution_is_deterministic() -> None:
    scope = _scope()
    answers = {scope.resolve(REMOTE, CLIENT) for _ in range(50)}
    assert answers == {CLIENT}


def test_resolution_returns_the_address_as_given() -> None:
    """Identity must be byte-identical to what the packet carried, never a
    reformatted form, or it would stop matching an enforcement target."""
    assert _scope().resolve(REMOTE, CLIENT) == CLIENT
    assert isinstance(_scope().resolve(REMOTE, CLIENT), str)
