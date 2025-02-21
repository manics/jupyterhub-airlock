import logging
from datetime import UTC, datetime
from pathlib import Path
from random import randint
from typing import Iterable

from .egress import EGRESS_FILE_DIR, Egress, EgressStatus, EgressStore
from .filesystemio import (
    copyfiles,
    filelist_and_size_recursive,
)

log = logging.getLogger("jupyterhub_airlock")

USER_EGRESS_DIR = "egress"


def timestamped_id(prefix: str) -> str:
    return "{0}/{1}-{2:08d}".format(
        prefix, datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f"), randint(0, 99999999)
    )


class UserEgressStore:
    def __init__(self, user_store: Path):
        self.user_store: Path = user_store.absolute()

    async def list_egress_files(
        self, user: str
    ) -> tuple[dict[Path, tuple[str, int]], int, Path]:
        """
        List all files in the egress directory for a given user

        Returns a Dict:
          key: relative file path
          value: tuple:
            - url-escaped file path
            - size (bytes)
        """
        user_egress_path = self.user_store / user / USER_EGRESS_DIR
        log.debug(f"Listing files in: {user_egress_path}")
        filelist, total_size = await filelist_and_size_recursive(user_egress_path)
        return filelist, total_size, user_egress_path

    async def new_egress(
        self, egress_store: EgressStore, user: str, requested_files: Iterable[str]
    ) -> Egress:
        filelist, _, user_egress_path = await self.list_egress_files(user)
        allowed_file_paths = filelist.keys()

        # The requested_files should be a subset of filelist
        # If it doesn't either the user has removed a file in the workspace
        # or someone is trying to hack the system
        requested_file_paths = set(Path(p) for p in requested_files)
        invalid_files = requested_file_paths.difference(allowed_file_paths)
        if invalid_files:
            log.error(
                f"Invalid file(s): {[str(p) for p in invalid_files]} not in ({[str(p) for p in allowed_file_paths]})"
            )
            raise ValueError(f"Invalid file(s): {[str(p) for p in invalid_files]}")

        if not requested_file_paths:
            raise ValueError("No files selected")

        log.debug(f"{requested_file_paths=}")

        egress_id = timestamped_id(user)
        egress = egress_store.new_egress(egress_id)
        egress_dest_path = egress.path / EGRESS_FILE_DIR

        await copyfiles(requested_file_paths, user_egress_path, egress_dest_path)
        log.debug(
            f"Copied {requested_files} from {user_egress_path} to {egress_dest_path}"
        )
        egress.add_files()
        return egress
