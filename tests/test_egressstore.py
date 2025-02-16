from jupyterhub_airlock.egress import (
    EgressStore,
    Egress,
    EgressStatus,
    is_valid_egress_id,
)
import json
import pytest


@pytest.mark.parametrize(
    "id,valid",
    [
        ("egress-1", True),
        ("123", True),
        ("a1", True),
        ("-123", False),
        ("abc 123", False),
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


def test_new_egress_invalid(tmp_path):
    with pytest.raises(ValueError) as exc_info:
        Egress("-123", tmp_path)
    assert exc_info.value.args[0] == "Invalid egress id -123"


def test_egressstore_new(tmp_path, egress_id):
    store = EgressStore(tmp_path)
    assert store.list() == []

    e = store.new_egress(egress_id)
    assert store.list() == [egress_id]
    assert e.id == egress_id
    assert e.path == tmp_path / egress_id
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == [
        egress_id,
        f"{egress_id}/files",
        f"{egress_id}/metadata.json",
    ]

    with open(str(tmp_path / egress_id / "metadata.json")) as f:
        assert json.load(f) == {"id": egress_id, "status": "new", "files": []}


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
    store = EgressStore(tmp_path)
    e = store.new_egress(egress_id)
    assert e.path == tmp_path / egress_id

    (e.path / "files" / "hello.txt").write_text("hello")
    (e.path / "files" / '{"}').mkdir()
    (e.path / "files" / '{"}' / "world.txt").write_text("world")

    e.add_files()

    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == [
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
            e.add_files()
        assert (
            exc_info.value.args[0]
            == "Can only add files to status new, current status pending"
        )
