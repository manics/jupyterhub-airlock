from jupyterhub_airlock.egress import (
    EgressStore,
    Egress,
    EgressStatus,
    is_valid_egress_id,
    is_valid_egress_component,
)
import json
import pytest
from conftest import random_egress_id
from pathlib import Path

HERE = Path(__file__).parent


@pytest.mark.parametrize(
    "id,valid",
    [
        ("user/egress-1", True),
        ("u1/123", True),
        ("a-1/a1", True),
        ("-123", False),
        ("u1/-123", False),
        ("aa/abc 123", False),
        ("a/bc123", False),
    ],
)
@pytest.mark.parametrize("raise_invalid", [True, False])
def test_is_valid_egress_id(id, valid, raise_invalid):
    if not valid and raise_invalid:
        with pytest.raises(ValueError) as exc_info:
            is_valid_egress_id(id)
        assert exc_info.value.args[0] == f"Invalid egress id {id}"
    else:
        assert is_valid_egress_id(id, raise_invalid) == valid


@pytest.mark.parametrize(
    "id,valid",
    [
        ("ab", True),
        ("a-b", True),
        ("a", False),
        ("ab/cd", False),
    ],
)
@pytest.mark.parametrize("raise_invalid", [True, False])
def test_is_valid_egress_component(id, valid, raise_invalid):
    if not valid and raise_invalid:
        with pytest.raises(ValueError) as exc_info:
            is_valid_egress_component(id)
        assert exc_info.value.args[0] == f"Invalid egress component {id}"
    else:
        assert is_valid_egress_component(id, raise_invalid) == valid


def test_new_egress_invalid(tmp_path):
    with pytest.raises(ValueError) as exc_info:
        Egress("-123", tmp_path)
    assert exc_info.value.args[0] == "Invalid egress id -123"


def test_egressstore_new(tmp_path, egress_id):
    u_id, e_id = egress_id.split("/")

    store = EgressStore(tmp_path)
    assert store.list("*") == []

    egress = store.new_egress(egress_id)
    assert store.list("*") == [egress_id]
    assert egress.id == egress_id
    assert egress.path == tmp_path / u_id / e_id
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == [
        u_id,
        egress_id,
        f"{egress_id}/files",
        f"{egress_id}/metadata.json",
    ]

    with open(str(tmp_path / egress_id / "metadata.json")) as f:
        assert json.load(f) == {"id": egress_id, "status": "new", "files": []}


def test_egressstore_list(tmp_path):
    store = EgressStore(tmp_path)
    assert store.list("*") == []

    u1 = random_egress_id().split("/")[0]
    u1e1 = random_egress_id().split("/")[1]
    u1e2 = random_egress_id().split("/")[1]

    u2 = random_egress_id().split("/")[0]
    u2e1 = random_egress_id().split("/")[1]

    u3 = random_egress_id().split("/")[0]

    for u, e in [(u1, u1e1), (u1, u1e2), (u2, u2e1)]:
        egress = store.new_egress(f"{u}/{e}")
        assert egress.metadata() == {"id": f"{u}/{e}", "status": "new", "files": []}

    assert store.list("*") == sorted([f"{u1}/{u1e1}", f"{u1}/{u1e2}", f"{u2}/{u2e1}"])
    assert store.list(u1) == sorted([f"{u1}/{u1e1}", f"{u1}/{u1e2}"])
    assert store.list(u2) == sorted([f"{u2}/{u2e1}"])
    assert store.list(u3) == []


def test_egressstatus_transitions(tmp_path, egress_id):
    store = EgressStore(tmp_path)
    e = store.new_egress(egress_id)

    with pytest.raises(ValueError) as exc_info:
        e.set_status(EgressStatus.ACCEPTED)
    assert (
        exc_info.value.args[0] == "Current status new, new status accepted is invalid"
    )

    with pytest.raises(ValueError) as exc_info:
        e.set_status(EgressStatus.REJECTED)
    assert (
        exc_info.value.args[0] == "Current status new, new status rejected is invalid"
    )


def test_egressstore_add_files(tmp_path, egress_id):
    u_id, e_id = egress_id.split("/")

    store = EgressStore(tmp_path)
    egress = store.new_egress(egress_id)
    assert egress.path == tmp_path / u_id / e_id

    (egress.path / "files" / "hello.txt").write_text("hello")
    (egress.path / "files" / '{"}').mkdir()
    (egress.path / "files" / '{"}' / "world.txt").write_text("world")

    egress.add_files()

    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == [
        u_id,
        egress_id,
        f"{egress_id}/files",
        f"{egress_id}/files/hello.txt",
        f'{egress_id}/files/{{"}}',
        f'{egress_id}/files/{{"}}/world.txt',
        f"{egress_id}/metadata.json",
    ]

    with open(str(tmp_path / egress_id / "metadata.json")) as f:
        assert json.load(f) == {
            "id": egress_id,
            "status": "pending",
            "files": [
                {
                    "path": "hello.txt",
                    "sha256sum": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                },
                {
                    "path": '{"}/world.txt',
                    "sha256sum": "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
                },
            ],
        }

        with pytest.raises(ValueError) as exc_info:
            egress.add_files()
        assert (
            exc_info.value.args[0]
            == "Can only add files to status new, current status pending"
        )


def test_unicode_files():
    store = EgressStore(HERE / "resources")
    assert store.list("*") == ["user-1/egress-123", "user-2/abc"]
    e = store.get_egress("user-2/abc")
    assert e.metadata() == {
        "id": "user-2/abc",
        "status": "pending",
        "files": [
            {
                "path": "birds 🐧🐔🦆.txt",
                "sha256sum": "620e834dad842f4baeb891b38f1db82b9c1c84401d2ba33f5a8036a856dc9719",
            }
        ],
    }
