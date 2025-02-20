import asyncio
import logging
from pathlib import Path
import shutil
import zipfile
from .egress import Egress
from typing import Dict, List, Tuple


from functools import wraps
from typing import Any, Callable, Awaitable, Coroutine

log = logging.getLogger("jupyterhub_airlock.download")


def to_thread[T, **P](func: Callable[P, T]) -> Callable[P, Awaitable[T]]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Coroutine[Any, Any, T]:
        return asyncio.to_thread(func, *args, **kwargs)

    return wrapper


OUTPUT_ZIP_NAME = "download.zip"
# https://docs.python.org/3/library/asyncio-eventloop.html#executing-code-in-thread-or-process-pools
# TODO: Check mixing Tornado and asyncio is allowed


@to_thread
def create_egress_zipfile(egress: Egress) -> Path:
    output = egress.path / OUTPUT_ZIP_NAME
    file_path_map = egress.files_for_egress()
    with zipfile.ZipFile(str(output), "w", zipfile.ZIP_DEFLATED) as zipf:
        for filepath, arcpath in file_path_map.items():
            zipf.write(filepath, arcpath)
    return output


@to_thread
def delete_egress_zipfile(egress: Egress) -> None:
    (egress.path / OUTPUT_ZIP_NAME).unlink


@to_thread
def copyfiles(filelist: List[Path], source: Path, dest: Path) -> None:
    for f in filelist:
        if f.is_absolute():
            raise ValueError(f"Expected relative paths, found {f}")
        if not f.is_file():
            raise ValueError(f"Not a file: {f}")

    for f in filelist:
        s = source / f
        d = dest / f
        d.mkdir(exist_ok=True)
        shutil.copy(s, d)


@to_thread
def filelist_and_size_recursive(dir: Path) -> Tuple[Dict[Path, int], int]:
    filelist = {}
    total_size = 0
    for p in dir.glob("**"):
        if p.is_file():
            filelist[p.relative_to(dir)] = p.stat().st_size
            total_size += p.stat().st_size
    return filelist, total_size
