#!/usr/bin/env python
"""
https://github.com/jupyterhub/jupyterhub/blob/5.0.0/examples/service-whoami/whoami-oauth.py
"""

from argparse import ArgumentParser, SUPPRESS
import asyncio
from datetime import datetime, UTC
import json
import os
from random import randint
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application
from tornado.web import RequestHandler
from tornado.web import HTTPError
from tornado.web import authenticated
from tornado.web import addslash
from tornado.web import url
from tornado.iostream import StreamClosedError


from jupyterhub.services.auth import HubOAuthCallbackHandler
from jupyterhub.services.auth import HubOAuthenticated
from jupyterhub.utils import url_path_join

from .egress import EgressStore, EgressStatus, Egress, EGRESS_FILE_DIR
from .filesystemio import create_egress_zipfile, delete_egress_zipfile
from .filesystemio import copyfiles, filelist_and_size_recursive, unescape_filepath


import logging
from http.client import responses

log = logging.getLogger("jupyterhub_airlock")

MAX_DIRECTORY_SIZE_MB = 100
USER_EGRESS_DIR = "egress"

# JUPYTERHUB_API_TOKEN = os.environ["JUPYTERHUB_API_TOKEN"]


def generate_egress_id(user: str) -> str:
    return "{0}/{1}-{2:08d}".format(
        user, datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f"), randint(0, 99999999)
    )


class HomeNoSlashHandler(RequestHandler):
    def get(self) -> None:
        self.redirect(self.settings["baseurl"])


class AirlockHandler(HubOAuthenticated, RequestHandler):  # type: ignore[misc]
    def initialize(self, **kwargs: Any) -> None:
        self.baseurl: str = kwargs.pop("baseurl")
        self.store: EgressStore = kwargs.pop("store")
        self.user_store: Path = kwargs.pop("user_store")
        if not self.store:
            raise ValueError("store required")
        self.admin_group = kwargs.pop("admin_group")
        if not self.admin_group:
            raise ValueError("admin_group required")
        super().initialize(**kwargs)

    def get_template_path(self) -> str:
        return os.path.join(os.path.dirname(__file__), "templates")

    def is_admin(self) -> bool:
        user = self.get_current_user()["name"]
        groups = self.get_current_user()["groups"]
        admin = self.admin_group in groups
        log.debug(f"is_admin {user} {groups}: {admin}")
        return admin

    def is_viewer(self, egress: Egress) -> bool:
        user = self.get_current_user()["name"]
        # TODO: Get user from metadata.json, not filepath
        u, _ = egress.id.split("/")
        viewer = self.is_admin() or (user == u)
        log.debug(f"is_viewer {user} {egress.id}: {viewer}")
        return viewer

    def is_reviewer(self, egress: Egress) -> bool:
        user = self.get_current_user()["name"]
        reviewer = self.is_admin() and egress.status() == EgressStatus.PENDING
        log.debug(f"is_reviewer {user} {egress.id}: {reviewer}")
        return reviewer

    def is_downloader(self, egress: Egress) -> bool:
        user = self.get_current_user()["name"]
        u, _ = egress.id.split("/")
        downloader = (
            self.is_admin() or (user == u)
        ) and egress.status() == EgressStatus.ACCEPTED
        log.debug(f"is_downloader {user} {egress.id}: {downloader}")
        return downloader

    @authenticated
    async def get(self) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")

        # token = JUPYTERHUB_API_TOKEN
        # http_client = AsyncHTTPClient()
        # response = await http_client.fetch(
        #     f"{self.hub_auth.api_url}/users/{current_user_model['name']}",
        #     headers={"Authorization": f"Bearer {token}"},
        # )
        # if response.error:
        #     raise HTTPError(500, reason="Failed to get user info")

        username = current_user_model["name"]
        groups = current_user_model["groups"]
        is_admin = self.admin_group in groups

        egress_list = self.store.list("*" if is_admin else username)
        self.render(
            "index.html",
            baseurl=self.baseurl,
            username=username,
            groups=groups,
            pending_list=egress_list.get(EgressStatus.PENDING, []),
            accepted_list=egress_list.get(EgressStatus.ACCEPTED, []),
            rejected_list=egress_list.get(EgressStatus.REJECTED, []),
            is_admin=is_admin,
        )

        # self.set_header("content-type", "application/json")
        # self.write(json.dumps(d, indent=2, sort_keys=True))
        # self.redirect(url)

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        exc_info = kwargs.get("exc_info")
        reason = responses.get(status_code, "Unknown HTTP Error")
        message = ""
        if exc_info:
            exception = exc_info[1]
            r = getattr(exception, "reason", "")
            if r:
                reason = r
            message = getattr(exception, "message", "")

        self.set_status(status_code, reason)
        self.render(
            "error.html", status_code=status_code, reason=reason, message=message
        )


# TODO: Break this into separate API/backend and frontend code
class AirlockSubmissionHandler(AirlockHandler):
    async def _list_egress_files(
        self, user: str
    ) -> tuple[dict[Path, tuple[str, int]], int, Path]:
        user_egress_path = self.user_store / user / USER_EGRESS_DIR
        log.debug(f"Listing files in: {user_egress_path}")
        filelist, total_size = await filelist_and_size_recursive(user_egress_path)
        return filelist, total_size, user_egress_path

    @addslash
    @authenticated
    async def get(self) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")
        username = current_user_model["name"]

        filelist, total_size, _ = await self._list_egress_files(username)
        total_size_mb = total_size / 1024 / 1024
        if total_size_mb > MAX_DIRECTORY_SIZE_MB:
            raise HTTPError(
                409,
                reason=f"Directory size {total_size_mb:.0f} MB exceeds maximum {MAX_DIRECTORY_SIZE_MB} MB",
            )

        self.render(
            "new.html",
            baseurl=self.baseurl,
            filelist=filelist,
            xsrf_token=self.xsrf_token.decode("ascii"),
        )

    @authenticated
    async def post(self) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")
        username = current_user_model["name"]

        log.debug(f"{self.request.arguments=}")

        filelist, _, user_egress_path = await self._list_egress_files(username)
        allowed_file_paths = filelist.keys()
        log.debug(f"{allowed_file_paths=}")

        request_arg_egress = self.request.arguments.get("egress")
        if request_arg_egress != [b"egress"]:
            log.error(f"Unexpected value for argument egress: {request_arg_egress}")
            raise HTTPError(400, reason="Unexpected form value")

        # The requested file should match filelist_and_size_recursive
        # If it doesn't either the user has removed a file in the workspace
        # or someone is trying to hack the system
        requested_files = set()
        for arg, value in self.request.arguments.items():
            if arg.startswith("file-"):
                if value != [b"on"]:
                    log.error(f"Unexpected value for argument {arg}: {value}")
                    raise HTTPError(400, reason="Unexpected form value")

                filepath = Path(unescape_filepath(arg[5:]))
                if filepath not in allowed_file_paths:
                    log.error(f"Invalid file argument: {arg} ({filepath})")
                    raise HTTPError(409, reason="Invalid file requested")
                else:
                    requested_files.add(filepath)

        if not requested_files:
            raise HTTPError(400, reason="No files selected")

        egress_id = generate_egress_id(username)
        egress = self.store.new_egress(egress_id)
        egress_dest_path = egress.path / EGRESS_FILE_DIR

        await copyfiles(requested_files, user_egress_path, egress_dest_path)
        log.debug(
            f"Copied {requested_files} from {user_egress_path} to {egress_dest_path}"
        )
        egress.add_files()

        self.redirect(f"{self.baseurl}egress/{egress_id}")


class AirlockEgressHandler(AirlockHandler):
    async def _egress_info(self, user: str, egress: str) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")
        username = current_user_model["name"]
        egress_id = f"{user}/{egress}"

        try:
            egress_item = self.store.get_egress(egress_id)
        except ValueError as e:
            # Some browser plugins make random requests like for installHook.js.map
            # So handle gracefully instead of filling up our logs with exceptions
            log.error(str(e))
            raise HTTPError(404, reason="Egress not found")

        is_reviewer = self.is_reviewer(egress_item)
        is_downloader = self.is_downloader(egress_item)
        if self.is_admin() or username == user or is_reviewer:
            self.render(
                "egress.html",
                baseurl=self.baseurl,
                egress=egress_item.metadata(),
                is_reviewer=is_reviewer,
                is_downloader=is_downloader,
                xsrf_token=self.xsrf_token.decode("ascii"),
            )
        else:
            raise HTTPError(404, reason="Egress not found")

    @addslash
    @authenticated
    async def get(self, user: str, egress: str) -> None:
        await self._egress_info(user, egress)

    @authenticated
    async def post(self, user: str, egress: str) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")

        egress_id = f"{user}/{egress}"
        egress_item = self.store.get_egress(egress_id)
        is_reviewer = self.is_reviewer(egress_item)

        if not is_reviewer:
            raise HTTPError(404, reason="Egress not found")

        log.debug(f"{self.request.arguments=}")

        accept = self.request.arguments.get("accept")
        if accept == [b"accept"]:
            egress_item.set_status(EgressStatus.ACCEPTED)
        elif accept == [b"reject"]:
            egress_item.set_status(EgressStatus.REJECTED)
        else:
            log.error(f"Invalid accept value: {accept}")
            raise HTTPError(422, "Invalid accept action")

        await self._egress_info(user, egress)


class AirlockDownloadHandler(AirlockHandler):
    async def _download(self, filepath: Path) -> None:
        # https://bhch.github.io/posts/2017/12/serving-large-files-with-tornado-safely-without-blocking/
        chunk_size = 1024 * 1024
        self.set_header("Content-Type", "application/force-download")
        self.set_header("Content-Disposition", f"attachment; filename={filepath.name}")

        with filepath.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                try:
                    self.write(chunk)
                    await self.flush()
                except StreamClosedError:
                    # client has closed the connection
                    break
                finally:
                    # delete chunk to free up memory
                    del chunk
                    # pause coroutine so other handlers can run
                    await asyncio.sleep(0.001)

    @authenticated
    async def post(self, user: str, egress: str) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")

        egress_id = f"{user}/{egress}"
        egress_item = self.store.get_egress(egress_id)
        is_downloader = self.is_downloader(egress_item)

        if not is_downloader:
            raise HTTPError(404, reason="Egress not found")

        log.debug(f"{self.request.arguments=}")

        download = self.request.arguments.get("download")
        if download != [b"download"]:
            log.error(f"Invalid download value: {download}")
            raise HTTPError(422, "Invalid download action")

        filepath = await create_egress_zipfile(egress_item)
        log.info(f"Downloading {filepath}")
        await self._download(filepath)
        log.debug(f"Download complete {filepath}")
        await delete_egress_zipfile(egress_item)


class HealthHandler(RequestHandler):
    async def get(self) -> None:
        self.set_header("content-type", "application/json")
        self.write(json.dumps({"status": "ok"}, indent=2, sort_keys=True))


def main(filestore: str, user_store: str, admin_group: str, debug: bool) -> None:
    JUPYTERHUB_SERVICE_PREFIX = os.getenv("JUPYTERHUB_SERVICE_PREFIX", "/")
    if not JUPYTERHUB_SERVICE_PREFIX.endswith("/"):
        JUPYTERHUB_SERVICE_PREFIX += "/"

    airlockArgs: dict[str, Any] = {}
    airlockArgs["store"] = EgressStore(Path(filestore))
    airlockArgs["admin_group"] = admin_group
    airlockArgs["user_store"] = Path(user_store).absolute()
    airlockArgs["baseurl"] = JUPYTERHUB_SERVICE_PREFIX

    def rule(p: str, handler: type[RequestHandler], *args: Any, **kwargs: Any) -> url:
        return url(
            url_path_join(JUPYTERHUB_SERVICE_PREFIX, p), handler, *args, **kwargs
        )

    # https://www.tornadoweb.org/en/stable/web.html#tornado.web.URLSpec
    app = Application(
        [
            rule("", HomeNoSlashHandler),
            rule("/", AirlockHandler, airlockArgs, name="home"),
            rule("/oauth_callback", HubOAuthCallbackHandler),
            # TODO: Enforce naming restrictions on user and server names in JupyterHub
            rule(
                r"/egress/(?P<user>[^/]+)/(?P<egress>[^/]+)/?",
                AirlockEgressHandler,
                airlockArgs,
            ),
            rule(
                r"/egress/(?P<user>[^/]+)/(?P<egress>[^/]+)/download",
                AirlockDownloadHandler,
                airlockArgs,
            ),
            rule(
                r"/new/?",
                AirlockSubmissionHandler,
                airlockArgs,
            ),
            # Health is always at the top level, not under baseurl
            ("/health/?", HealthHandler),
        ],
        static_url_prefix=url_path_join(JUPYTERHUB_SERVICE_PREFIX, "static/"),
        cookie_secret=os.urandom(32),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        debug=debug,
        baseurl=JUPYTERHUB_SERVICE_PREFIX,
    )

    http_server = HTTPServer(app)

    jh_service_url = os.getenv("JUPYTERHUB_SERVICE_URL")
    if jh_service_url:
        u = urlparse(jh_service_url)
        hostname = u.hostname
        port = int(u.port) if u.port else 8041
    else:
        hostname = ""
        port = 8041

    log.info(f"Listening on {hostname}:{port}")
    http_server.listen(port, hostname)
    IOLoop.current().start()


if __name__ == "__main__":
    parser = ArgumentParser("JupyterHub Guacamole handler")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    parser.add_argument("--debug", action="store_true", help=SUPPRESS)
    parser.add_argument("--filestore", required=True, help="Egress filestore directory")
    parser.add_argument(
        "--userstore", required=True, help="User workspace egress filestore"
    )
    parser.add_argument(
        "--admin-group", default="egress-admins", help="Egress admin group"
    )
    args = parser.parse_args()

    log_level = "DEBUG" if args.debug else args.log_level.upper()
    log.setLevel(log_level)
    h = logging.StreamHandler()
    h.setFormatter(
        logging.Formatter(
            "[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s"
        )
    )
    log.addHandler(h)
    main(args.filestore, args.userstore, args.admin_group, args.debug)
