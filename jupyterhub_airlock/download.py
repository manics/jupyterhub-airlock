import asyncio
import concurrent.futures
import logging
from pathlib import Path
import zipfile
from .egress import Egress

log = logging.getLogger("jupyterhub_airlock.download")

OUTPUT_ZIP_NAME = "download.zip"
# https://docs.python.org/3/library/asyncio-eventloop.html#executing-code-in-thread-or-process-pools
# TODO: Check mixing Tornado and asyncio is allowed


def _create_egress_zipfile(egress: Egress) -> Path:
    output = egress.path / OUTPUT_ZIP_NAME
    file_path_map = egress.files_for_egress()
    with zipfile.ZipFile(str(output), "w", zipfile.ZIP_DEFLATED) as zipf:
        for filepath, arcpath in file_path_map.items():
            zipf.write(filepath, arcpath)
    return output


async def create_egress_zipfile(egress: Egress) -> Path:
    loop = asyncio.get_running_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, _create_egress_zipfile, egress)
    return result


async def delete_egress_zipfile(egress: Egress) -> None:
    (egress.path / OUTPUT_ZIP_NAME).unlink()
