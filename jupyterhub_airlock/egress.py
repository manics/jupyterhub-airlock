from enum import Enum
import hashlib
from pathlib import Path
from typing import Any, Dict, List, TypeAlias
import json
import re

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
    _egress_status_values = set(e.value for e in EgressStatus)

    def __init__(self, id: str, path: Path, create: bool = False):
        is_valid_egress_id(id)
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

    def metadata(self) -> JsonT:
        """
        Returns egress metadata
        """
        m = self.path / "metadata.json"
        if not m.exists() or not m.is_file():
            raise ValueError(f"Metadata for egress {self.id} not found")
        return json.loads(m.read_text())

    def update_metadata(self, d: Dict[str, object], create: bool = False) -> None:
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


class EgressStore:
    def __init__(self, filestore: Path):
        self.filestore: Path = filestore

    def list(self, user: str) -> List[str]:
        """
        List all egresses
        """
        if user != "*":
            is_valid_egress_component(user)
        dirs = [
            f.relative_to(self.filestore) for f in self.filestore.glob(f"{user}/*/")
        ]
        return sorted(str(d) for d in dirs if is_valid_egress_id(str(d)))

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
