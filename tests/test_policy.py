"""Phase 1 — Policy tests. Pure Python; run anywhere."""
from __future__ import annotations

import pytest

from temenos import Policy, PolicyViolation


# -- construction / defaults ----------------------------------------------------------

def test_default_policy_fs_locked_network_open():
    p = Policy()
    assert p.read == () and p.write == ()          # filesystem locked (overlay only)
    assert p.network == "host"                      # default: host network passthrough
    assert bool(p.network) is True
    assert p.max_memory_mb == 256


def test_network_truthiness_still_means_what_v1_meant():
    """`network` grew from a bool to three modes. The natural v1 expression —
    `if policy.network:` — has to keep meaning "has network", or a plain
    string (`bool("none") is True`) would silently treat an isolated box as a
    connected one and nothing would fail."""
    assert bool(Policy(network=False).network) is False
    assert bool(Policy(network="none").network) is False
    assert bool(Policy(network=True).network) is True
    assert bool(Policy(network="filtered", allow_hosts=["a.com"]).network) is True

def test_lists_are_coerced_to_tuples_and_deduped():
    p = Policy(read=["/a", "/b", "/a"])
    assert p.read == ("/a", "/b")
    assert isinstance(p.read, tuple)

def test_frozen_and_hashable():
    p = Policy(read=["/a"])
    with pytest.raises(Exception):
        p.read = ("/b",)            # type: ignore[misc]
    assert hash(p) == hash(Policy(read=["/a"]))
    assert p == Policy(read=["/a"])

def test_string_for_set_field_is_rejected():
    with pytest.raises(TypeError):
        Policy(read="/a")           # a bare string is almost never intended

def test_negative_limit_rejected():
    with pytest.raises(ValueError):
        Policy(max_memory_mb=-1)

def test_unknown_field_rejected():
    with pytest.raises(TypeError):
        Policy(trust="nonsense")    # type: ignore[call-arg]  — field removed in v1


# -- restrict() -----------------------------------------------------------------------

def test_restrict_narrows():
    parent = Policy(read=["/a", "/b"], network=True, max_memory_mb=512)
    child = parent.restrict(read=["/a"], network=False, max_memory_mb=128)
    assert child.read == ("/a",)
    assert child.network == "none"
    assert child.max_memory_mb == 128

def test_restrict_inherits_unpassed_fields():
    parent = Policy(read=["/a"], write=["/w"], max_cpu_seconds=10)
    child = parent.restrict(read=["/a"])
    assert child.write == ("/w",)
    assert child.max_cpu_seconds == 10

def test_restrict_noargs_returns_equal_policy():
    parent = Policy(read=["/a"], max_memory_mb=300)
    assert parent.restrict() == parent

@pytest.mark.parametrize("kwargs", [
    {"read": ["/a", "/c"]},               # add a path not in parent
    {"network": True},                    # enable network (parent has none)
    {"max_memory_mb": 1024},              # raise a limit
    {"max_processes": 999},
])
def test_restrict_widening_raises(kwargs):
    parent = Policy(read=["/a"], network=False, max_memory_mb=512, max_processes=16)
    with pytest.raises(PolicyViolation):
        parent.restrict(**kwargs)


def test_restrict_can_disable_network_not_enable():
    assert Policy(network=True).restrict(network=False).network == "none"
    with pytest.raises(PolicyViolation):
        Policy(network=False).restrict(network=True)


def test_restrict_walks_down_the_modes_and_never_up():
    """host > filtered > none. Narrowing to a *tighter* mode is the only
    direction, and every step of it is a step somebody can take."""
    host = Policy(network="host")
    assert host.restrict(network="filtered").network == "filtered"
    assert host.restrict(network="none").network == "none"

    filtered = Policy(network="filtered", allow_hosts=["a.com"])
    assert filtered.restrict(network="none").network == "none"
    with pytest.raises(PolicyViolation):
        filtered.restrict(network="host")
    with pytest.raises(PolicyViolation):
        Policy(network="none").restrict(network="filtered")


def test_narrowing_out_of_filtered_drops_the_allowlist():
    """A box that no longer filters must not carry hosts nothing consults —
    that reads like containment and is not."""
    filtered = Policy(network="filtered", allow_hosts=["a.com"])
    assert filtered.restrict(network="none").allow_hosts == ()


def test_an_allowlist_without_filtering_is_refused():
    with pytest.raises(ValueError):
        Policy(network="host", allow_hosts=["a.com"])
    with pytest.raises(ValueError):
        Policy(network=False, allow_hosts=["a.com"])


def test_network_modes_default_and_coerce():
    assert Policy().network == "host"                # default is host passthrough
    assert Policy(network=False).network == "none"
    assert Policy(network=True).network == "host"
    assert Policy(network="host").network == "host"
    assert Policy(network="none").network == "none"
    assert Policy(network="filtered", allow_hosts=["a.com"]).network == "filtered"
    assert Policy(network="proxy", allow_hosts=["a.com"]).network == "filtered"
    with pytest.raises(ValueError):
        Policy(network="evil.com")        # a host is not a mode
    with pytest.raises(ValueError):
        Policy(network=["a", "b"])         # nor is a list

def test_restrict_unknown_field_raises_typeerror():
    with pytest.raises(TypeError):
        Policy().restrict(memory_mb=10)   # typo'd field name

def test_no_escalate_method():
    assert not hasattr(Policy(), "escalate")


# -- from_dict / to_dict round trip ---------------------------------------------------

def test_round_trip():
    p = Policy(read=["/p"], write=["/w"], network=True, max_memory_mb=384)
    assert Policy.from_dict(p.to_dict()) == p

def test_from_dict_rejects_unknown_key():
    with pytest.raises(ValueError):
        Policy.from_dict({"reads": ["/a"]})


# -- semantic checks ------------------------------------------------------------------

def test_allows_path_read_and_write():
    p = Policy(read=["/project"], write=["/project/out"])
    assert p.allows_path_read("/project/src/main.py")
    assert p.allows_path_read("/project")              # exact base
    assert p.allows_path_read("/project/out/x")        # writable implies readable
    assert not p.allows_path_read("/etc/passwd")
    assert p.allows_path_write("/project/out/x")
    assert not p.allows_path_write("/project/src/main.py")

def test_path_prefix_is_not_fooled_by_sibling():
    p = Policy(read=["/foo"])
    assert p.allows_path_read("/foo/bar")
    assert not p.allows_path_read("/foobar")           # /foobar is not under /foo

def test_root_read_allows_everything():
    assert Policy(read=["/"]).allows_path_read("/etc/hosts")

def test_network_round_trips_as_a_mode():
    assert Policy(network=True).to_dict()["network"] == "host"
    assert Policy.from_dict({"network": "host"}).network == "host"
    # Plain `str` in the dict, so JSON round-trips without a custom encoder.
    assert type(Policy(network=True).to_dict()["network"]) is str

    filtered = Policy(network="filtered", allow_hosts=["*.acme.com"])
    assert Policy.from_dict(filtered.to_dict()) == filtered


def test_checkpoint_mode_defaults_and_validates():
    assert Policy().checkpoint == "auto"
    assert Policy(checkpoint="off").checkpoint == "off"
    with pytest.raises(ValueError):
        Policy(checkpoint="sometimes")
    assert Policy.from_dict(Policy(checkpoint="on-close").to_dict()).checkpoint == "on-close"


def test_scratch_defaults_to_disk_and_validates():
    assert Policy().scratch == "disk"                 # checkpointable by default
    assert Policy(scratch="memory").scratch == "memory"
    with pytest.raises(ValueError):
        Policy(scratch="ram")
    assert Policy.from_dict(Policy(scratch="memory").to_dict()).scratch == "memory"
