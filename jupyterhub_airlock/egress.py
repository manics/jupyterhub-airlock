import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from typing import Any, TypeAlias

JsonT: TypeAlias = Any

EGRESS_FILE_DIR = "files"
EGRESS_COMPONENT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9-]+$"
EGRESS_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9-]+/[A-Za-z0-9][A-Za-z0-9-]+$"


class EgressStatus(Enum):
    NEW = "new"
    CANCELLED = "cancelled"
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"

    def __str__(self) -> str:
        return str(self.value)


EgressStatus_transitions = {
    EgressStatus.NEW: {EgressStatus.PENDING, EgressStatus.CANCELLED},
    EgressStatus.CANCELLED: {},
    EgressStatus.PENDING: {EgressStatus.ACCEPTED, EgressStatus.REJECTED},
    EgressStatus.ACCEPTED: {},
    EgressStatus.REJECTED: {},
}


def is_valid_egress_id(id: str, raise_invalid: bool = True) -> bool:
    """
    Checks whether an egress id string is allowed
    """
    if not re.match(EGRESS_ID_PATTERN, id):
        if not raise_invalid:
            return False
        raise ValueError(f"Invalid egress id {id}")
    return True


def is_valid_egress_component(id: str, raise_invalid: bool = True) -> bool:
    """
    Checks whether an egress component string is allowed
    """
    if not re.match(EGRESS_COMPONENT_PATTERN, id):
        if not raise_invalid:
            return False
        raise ValueError(f"Invalid egress component {id}")
    return True


class Egress:
    def __init__(self, id: str, path: Path, create: bool = False):
        is_valid_egress_id(id)
        if not path.is_absolute():
            raise ValueError(f"Path {path} must be absolute")
        self.id = id
        self.path = path
        if create:
            if self.path.exists():
                raise ValueError(f"Egress {id} already exists")
            (self.path / "files").mkdir(parents=True)
            self.update_metadata(
                {"id": id, "status": EgressStatus.NEW.value, "files": []},
                create=True,
            )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Egress):
            return NotImplemented
        return self.id == other.id and self.path == other.path

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.id, self.path))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.id!r},{self.path!r})"

    def metadata(self) -> JsonT:
        """
        Returns egress metadata
        """
        m = self.path / "metadata.json"
        if not m.exists() or not m.is_file():
            raise ValueError(f"Metadata for egress {self.id} not found")
        return json.loads(m.read_text())

    def update_metadata(self, d: dict[str, object], create: bool = False) -> None:
        """
        Update some metadata key-value pairs
        """
        if create:
            m = {}
        else:
            m = self.metadata()
        for k, v in d.items():
            m[k] = v
        json_m = json.dumps(m, indent=2)
        metadata_file = self.path / "metadata.json"
        metadata_file.write_text(json_m)

    def status(self) -> EgressStatus:
        """
        Get the egress status
        """
        m = self.metadata()
        status = m["status"]
        return EgressStatus(status)

    def set_status(self, status: EgressStatus) -> None:
        """
        Change the egress status
        """
        current = self.status()
        if status not in EgressStatus_transitions[current]:
            raise ValueError(
                f"Current status {current}, new status {status} is invalid"
            )
        self.update_metadata({"status": status.value})

    def add_files(self) -> None:
        """
        Updates egress metadata.json with the recursive list of files in this directory
        """
        current = self.status()
        if current != EgressStatus.NEW:
            raise ValueError(
                f"Can only add files to status {EgressStatus.NEW}, current status {current}"
            )
        files = []
        d = self.path / EGRESS_FILE_DIR
        for f in d.rglob("*"):
            if f.is_dir():
                continue
            if not f.is_file():
                raise ValueError(f"Not a standard file: {f}")
            with open(str(f), "rb") as fh:
                h = hashlib.file_digest(fh, hashlib.sha256)
                files.append(
                    {"path": str(f.relative_to(d)), "sha256sum": h.hexdigest()}
                )
        self.update_metadata({"files": files})
        self.set_status(EgressStatus.PENDING)

    def files_for_egress(self) -> dict[str, str]:
        """
        Return a map of {absolute_file_path : egress_file_path}
        for constructing downloadable outputs
        Includes the root metadata.json
        """
        status = self.status()
        if status != EgressStatus.ACCEPTED:
            raise ValueError(
                f"Egress must be {EgressStatus.ACCEPTED}, current status {status}"
            )
        file_path_map = {str(self.path / "metadata.json"): "metadata.json"}
        for file in self.metadata()["files"]:
            file_path_map[str(self.path / EGRESS_FILE_DIR / file["path"])] = (
                f"{EGRESS_FILE_DIR}/{file['path']}"
            )
        return file_path_map


EgressList: TypeAlias = dict[EgressStatus, dict[str, Egress]]


class EgressStore:
    def __init__(self, filestore: Path):
        self.filestore: Path = filestore.absolute()

    def _list_filestore(self, user: str) -> EgressList:
        """
        Get all egress in a filestore, optionally filtered by user

        TODO: Need a database, loading all egress metadata files repeatedly
        on basically every request is obviously inefficient
        """
        egresses: EgressList = {}
        for f in self.filestore.glob(f"{user}/*/"):
            id = str(f.relative_to(self.filestore))
            if is_valid_egress_id(id):
                egress = Egress(id, f)
                status = egress.status()
            try:
                egresses[status][id] = egress
            except KeyError:
                egresses[status] = {id: egress}
        return egresses

    def list(self, user: str) -> EgressList:
        """
        List all egresses
        """
        if user != "*":
            is_valid_egress_component(user)
        return self._list_filestore(user)

    def get_egress(self, egress_id: str) -> Egress:
        """
        Get an egress
        """
        is_valid_egress_id(egress_id)
        e = self.filestore / egress_id
        if not e.exists() or not e.is_dir():
            raise ValueError(f"Egress {egress_id} not found")
        return Egress(egress_id, e)

    def new_egress(self, egress_id: str) -> Egress:
        """
        Create a new empty egress
        """
        u_id, e_id = egress_id.split("/")
        path = self.filestore / u_id / e_id
        egress = Egress(egress_id, path, create=True)
        return egress
