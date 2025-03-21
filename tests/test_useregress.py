import datetime
import json
import os
from pathlib import Path
from shutil import copytree

import pytest

import jupyterhub_airlock.user_egress
from jupyterhub_airlock.egress import EgressStore
from jupyterhub_airlock.user_egress import UserEgressStore, timestamped_id

HERE = Path(__file__).parent


@pytest.fixture
def patch_datetime_now(monkeypatch):
    class mockdatetime(datetime.datetime):
        @classmethod
        def now(cls, tz):
            assert tz == datetime.UTC
            return datetime.datetime(2025, 1, 23, 12, 34, 56)

    monkeypatch.setattr(jupyterhub_airlock.user_egress, "datetime", mockdatetime)


@pytest.fixture
def tmp_stores(tmp_path):
    user_path = tmp_path / "users"
    egress_path = tmp_path / "egress"

    groupname = "group-1"
    username = "user-1"
    d = user_path / groupname / username / "@^'🦆" / "multi" / "level"
    d.mkdir(parents=True)
    (d / "hello.txt").write_text("hello\n")
    (user_path / groupname / username / "a.txt").write_text("\n\n")
    return user_path, egress_path, groupname, username


def test_timestamped_id(patch_datetime_now):
    id = timestamped_id("test")
    assert id.startswith("test/20250123-123456-000000-")


@pytest.mark.asyncio
async def test_list_egress_files(tmp_stores):
    user_path, egress_path, groupname, username = tmp_stores
    store = UserEgressStore(user_path)

    for g, u in [(groupname, "nonexistent-user"), ("nonexistent-group", username)]:
        filelist, total_size, user_egress_path = await store.list_egress_files(g, u)
        assert filelist == {}
        assert total_size == 0
        assert user_egress_path == Path(user_path / g / u)

    filelist, total_size, user_egress_path = await store.list_egress_files(
        groupname, username
    )
    assert filelist == {
        Path("@^'🦆/multi/level/hello.txt"): (
            "%40%5E%27%F0%9F%A6%86%2Fmulti%2Flevel%2Fhello.txt",
            6,
        ),
        Path("a.txt"): ("a.txt", 2),
    }
    assert total_size == 8
    assert user_egress_path == (user_path / groupname / username)


@pytest.mark.asyncio
async def test_new_egress(tmp_stores, patch_datetime_now):
    user_path, egress_path, groupname, username = tmp_stores
    user_store = UserEgressStore(user_path)
    egress_store = EgressStore(egress_path)

    requested_files = ["@^'🦆/multi/level/hello.txt", "a.txt"]

    e = await user_store.new_egress(egress_store, groupname, username, requested_files)
    metadata = e.metadata()
    # Lookup random suffix
    random_suffix = metadata["id"][-8:]

    assert metadata == {
        "id": f"{groupname}/{username}/20250123-123456-000000-{random_suffix}",
        "status": "pending",
        "files": [
            {
                "path": "a.txt",
                "sha256sum": "75a11da44c802486bc6f65640aa48a730f0f684c5c07a42ba3cd1735eb3fb070",
            },
            {
                "path": "@^'🦆/multi/level/hello.txt",
                "sha256sum": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
            },
        ],
    }

    ls_recursive = sorted(
        str(p.relative_to(egress_path)) for p in egress_path.glob("**/*")
    )
    assert ls_recursive == [
        groupname,
        f"{groupname}/{username}",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/files",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/files/@^'🦆",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/files/@^'🦆/multi",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/files/@^'🦆/multi/level",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/files/@^'🦆/multi/level/hello.txt",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/files/a.txt",
        f"{groupname}/{username}/20250123-123456-000000-{random_suffix}/metadata.json",
    ]


@pytest.mark.asyncio
async def test_new_egress_nofiles(tmp_stores):
    user_path, egress_path, groupname, username = tmp_stores
    user_store = UserEgressStore(user_path)
    egress_store = EgressStore(egress_path)

    with pytest.raises(ValueError) as exc_info:
        await user_store.new_egress(egress_store, groupname, username, [])
    assert exc_info.value.args[0] == "No files selected"


@pytest.mark.asyncio
async def test_new_egress_invalidfiles(tmp_stores):
    user_path, egress_path, groupname, username = tmp_stores
    user_store = UserEgressStore(user_path)
    egress_store = EgressStore(egress_path)

    with pytest.raises(ValueError) as exc_info:
        await user_store.new_egress(
            egress_store, groupname, username, ["a.txt", "b.txt"]
        )
    assert exc_info.value.args[0] == "Invalid file(s): ['b.txt']"
