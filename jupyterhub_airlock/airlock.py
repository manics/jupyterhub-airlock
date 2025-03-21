"""
https://github.com/jupyterhub/jupyterhub/blob/5.0.0/examples/service-whoami/whoami-oauth.py
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from http.client import responses
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jupyterhub.services.auth import HubOAuthCallbackHandler, HubOAuthenticated
from jupyterhub.utils import url_path_join
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.web import (
    Application,
    HTTPError,
    RedirectHandler,
    RequestHandler,
    addslash,
    authenticated,
    url,
)

from ._version import version
from .egress import EGRESS_FILE_DIR, Egress, EgressList, EgressStatus, EgressStore
from .filesystemio import (
    create_egress_zipfile,
    delete_egress_zipfile,
    unescape_filepath,
)
from .user_egress import UserEgressStore

log = logging.getLogger(__name__)

MAX_DIRECTORY_SIZE_MB = 100

# JUPYTERHUB_API_TOKEN = os.environ["JUPYTERHUB_API_TOKEN"]


class AirlockException(HTTPError):
    def __init__(
        self, status: int, *args: Any, message: str | None = None, **kwargs: Any
    ):
        self.timestamp = datetime.now().isoformat()
        self.message = message
        super().__init__(*args, **kwargs)


class AirlockHandler(HubOAuthenticated, RequestHandler):  # type: ignore[misc]
    def initialize(self, **kwargs: Any) -> None:
        self.baseurl: str = kwargs.pop("baseurl")
        self.jupyterhub_home: str = kwargs.pop("jupyterhub_home")

        self.store: EgressStore = kwargs.pop("store")
        self.user_store: UserEgressStore = kwargs.pop("user_store")
        if not self.store:
            raise ValueError("store required")
        if not self.user_store:
            raise ValueError("user_store required")

        self.admin_group = kwargs.pop("admin_group")
        if not self.admin_group:
            raise ValueError("admin_group required")

        super().initialize(**kwargs)

    def get_template_path(self) -> str:
        return os.path.join(os.path.dirname(__file__), "templates")

    def get_template_namespace(self) -> dict[str, Any]:
        """
        Provides default variables that are included in all templates
        """
        ns = super().get_template_namespace()
        ns["baseurl"] = self.baseurl
        ns["version"] = version
        ns["jupyterhub_home"] = self.jupyterhub_home

        user = self.get_current_user()
        if user:
            ns["username"] = user.get("name")
            ns["groups"] = user.get("groups")
            ns["is_admin"] = self.is_admin()
        else:
            ns["username"] = None
            ns["groups"] = None
            ns["is_admin"] = None
        return ns

    def is_admin(self) -> bool:
        user = self.get_current_user()
        if user:
            username = user["name"]
            groups = user["groups"]
            admin = self.admin_group in groups
            log.debug(f"is_admin {username} {groups}: {admin}")
            return admin
        return False

    def is_viewer(self, egress: Egress) -> bool:
        user = self.get_current_user()["name"]
        groups = self.get_current_user()["groups"]
        # TODO: Get user from metadata.json, not filepath
        g, u, _ = egress.id.split("/")
        viewer = self.is_admin() or (g in groups and user == u)
        log.debug(f"is_viewer {groups} {user} {egress.id}: {viewer}")
        return viewer

    def is_reviewer(self, egress: Egress) -> bool:
        user = self.get_current_user()["name"]
        groups = self.get_current_user()["groups"]
        reviewer = self.is_admin() and egress.status() == EgressStatus.PENDING
        log.debug(f"is_reviewer {groups} {user} {egress.id}: {reviewer}")
        return reviewer

    def is_downloader(self, egress: Egress) -> bool:
        user = self.get_current_user()["name"]
        groups = self.get_current_user()["groups"]
        g, u, _ = egress.id.split("/")
        downloader = (
            self.is_admin() or (g in groups and user == u)
        ) and egress.status() == EgressStatus.ACCEPTED
        log.debug(f"is_downloader {groups} {user} {egress.id}: {downloader}")
        return downloader

    @addslash
    @authenticated
    async def get(self) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise AirlockException(403, message="Missing user")

        # token = JUPYTERHUB_API_TOKEN
        # http_client = AsyncHTTPClient()
        # response = await http_client.fetch(
        #     f"{self.hub_auth.api_url}/users/{current_user_model['name']}",
        #     headers={"Authorization": f"Bearer {token}"},
        # )
        # if response.error:
        #     raise AirlockException(500, message="Failed to get user info")

        username = current_user_model["name"]
        groups = current_user_model["groups"]
        is_admin = self.admin_group in groups

        egress_list: EgressList = {}
        if is_admin:
            egress_list = self.store.list("*", "*")
        else:
            for group in groups:
                es = self.store.list(group, username)
                for status, egresses in es.items():
                    if status not in egress_list:
                        egress_list[status] = {}
                    overlap = set(egress_list[status].keys()).intersection(
                        egresses.keys()
                    )
                    if overlap:
                        raise RuntimeError(f"Duplicate egress ids found: {overlap}")
                    egress_list[status].update(egresses)

        self.render(
            "index.html",
            pending_list=sorted(
                egress_list.get(EgressStatus.PENDING, []), reverse=True
            ),
            accepted_list=sorted(
                egress_list.get(EgressStatus.ACCEPTED, []), reverse=True
            ),
            rejected_list=sorted(
                egress_list.get(EgressStatus.REJECTED, []), reverse=True
            ),
        )

        # self.set_header("content-type", "application/json")
        # self.write(json.dumps(d, indent=2, sort_keys=True))
        # self.redirect(url)

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        exc_info = kwargs.get("exc_info")
        reason = responses.get(status_code, "Unknown HTTP Error")
        message = ""
        timestamp = ""
        if exc_info:
            exception = exc_info[1]
            r = getattr(exception, "reason", "")
            if r:
                reason = r
            message = getattr(exception, "message", "")
            timestamp = getattr(exception, "timestamp", "")

        self.set_status(status_code, reason)
        self.render(
            "error.html",
            status_code=status_code,
            reason=reason,
            message=message,
            timestamp=timestamp,
        )


class AirlockSubmissionHandler(AirlockHandler):
    def _request_arg_group(self) -> str:
        """
        Get the value of the group form field
        Check the user is a member of the group
        """
        groups = self.get_current_user()["groups"]
        req_group = self.request.arguments.get("group")
        if not req_group or len(req_group) != 1:
            log.error(f"Expected one group: {req_group}")
            raise AirlockException(422, message="Expected one group")
        group = req_group[0].decode()
        if group not in groups:
            raise AirlockException(404, message="Egress not found")
        return group

    @addslash
    @authenticated
    async def get(self) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise AirlockException(403, message="Missing user")
        username = current_user_model["name"]
        groups = current_user_model["groups"]

        new_button = self.request.arguments.get("new")
        if new_button != [b"new"]:
            log.error(f"Invalid new value: {new_button}")
            raise AirlockException(422, message="Invalid new action")

        group = self._request_arg_group()

        filelist, total_size, _ = await self.user_store.list_egress_files(
            group, username
        )
        total_size_mb = total_size / 1024 / 1024
        if total_size_mb > MAX_DIRECTORY_SIZE_MB:
            raise AirlockException(
                409,
                message=f"Directory size {total_size_mb:.0f} MB exceeds maximum {MAX_DIRECTORY_SIZE_MB} MB",
            )

        self.render(
            "new.html",
            filelist=filelist,
            xsrf_token=self.xsrf_token.decode("ascii"),
            group=group,
        )

    @authenticated
    async def post(self) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise AirlockException(403, message="Missing user")
        username = current_user_model["name"]
        groups = current_user_model["groups"]

        log.debug(f"{self.request.arguments=}")

        group = self._request_arg_group()
        request_arg_egress = self.request.arguments.get("egress")
        if request_arg_egress != [b"egress"]:
            log.error(f"Unexpected value for argument egress: {request_arg_egress}")
            raise AirlockException(400, message="Unexpected form value")

        requested_files = set()
        for arg, value in self.request.arguments.items():
            if arg.startswith("file-"):
                if value != [b"on"]:
                    log.error(f"Unexpected value for argument {arg}: {value}")
                    raise AirlockException(400, message="Unexpected form value")
                filepath = unescape_filepath(arg[5:])
                requested_files.add(filepath)

        try:
            egress = await self.user_store.new_egress(
                self.store, group, username, requested_files
            )
        except ValueError as e:
            log.error(f"Failed to create new egress: {e}")
            raise AirlockException(400, message="Failed to create new egress") from e

        self.redirect(f"{self.baseurl}egress/{egress.id}")


class AirlockEgressHandler(AirlockHandler):
    async def _egress_info(self, group: str, user: str, egress: str) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise AirlockException(403, message="Missing user")
        egress_id = f"{group}/{user}/{egress}"

        try:
            egress_item = self.store.get_egress(egress_id)
        except ValueError as e:
            # Some browser plugins make random requests like for installHook.js.map
            # So handle gracefully instead of filling up our logs with exceptions
            log.error(str(e))
            raise AirlockException(404, message="Egress not found")

        is_viewer = self.is_viewer(egress_item)
        is_reviewer = self.is_reviewer(egress_item)
        is_downloader = self.is_downloader(egress_item)
        if self.is_admin() or is_viewer or is_reviewer:
            self.render(
                "egress.html",
                egress=egress_item.metadata(),
                is_reviewer=is_reviewer,
                is_downloader=is_downloader,
                xsrf_token=self.xsrf_token.decode("ascii"),
            )
        else:
            raise AirlockException(404, message="Egress not found")

    @addslash
    @authenticated
    async def get(self, group: str, user: str, egress: str) -> None:
        await self._egress_info(group, user, egress)

    @authenticated
    async def post(self, group: str, user: str, egress: str) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise AirlockException(403, message="Missing user")

        egress_id = f"{group}/{user}/{egress}"
        egress_item = self.store.get_egress(egress_id)
        is_reviewer = self.is_reviewer(egress_item)

        if not is_reviewer:
            raise AirlockException(404, message="Egress not found")

        log.debug(f"{self.request.arguments=}")

        accept = self.request.arguments.get("accept")
        if accept == [b"accept"]:
            egress_item.set_status(EgressStatus.ACCEPTED)
        elif accept == [b"reject"]:
            egress_item.set_status(EgressStatus.REJECTED)
        else:
            log.error(f"Invalid accept value: {accept}")
            raise AirlockException(422, message="Invalid accept action")

        await self._egress_info(group, user, egress)


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
    async def post(self, group: str, user: str, egress: str) -> None:
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise AirlockException(403, message="Missing user")

        egress_id = f"{group}/{user}/{egress}"
        egress_item = self.store.get_egress(egress_id)
        is_downloader = self.is_downloader(egress_item)

        if not is_downloader:
            raise AirlockException(404, message="Egress not found")

        log.debug(f"{self.request.arguments=}")

        download = self.request.arguments.get("download")
        if download != [b"download"]:
            log.error(f"Invalid download value: {download}")
            raise AirlockException(422, message="Invalid download action")

        filepath = await create_egress_zipfile(egress_item)
        log.info(f"Downloading {filepath}")
        await self._download(filepath)
        log.debug(f"Download complete {filepath}")
        await delete_egress_zipfile(egress_item)


class HealthHandler(RequestHandler):
    async def get(self) -> None:
        self.set_header("content-type", "application/json")
        self.write(json.dumps({"status": "ok"}, indent=2, sort_keys=True))


def airlock(filestore: str, user_store: str, admin_group: str, debug: bool) -> None:
    JUPYTERHUB_SERVICE_PREFIX = os.getenv("JUPYTERHUB_SERVICE_PREFIX", "/")
    if not JUPYTERHUB_SERVICE_PREFIX.endswith("/"):
        JUPYTERHUB_SERVICE_PREFIX += "/"

    # https://jupyterhub.readthedocs.io/en/5.2.1/reference/services.html#launching-a-hub-managed-service
    jupyterhub_url = os.getenv(
        "JUPYTERHUB_PUBLIC_HUB_URL", os.getenv("JUPYTERHUB_BASE_URL")
    )
    if not jupyterhub_url:
        jupyterhub_url = "/"

    airlockArgs: dict[str, Any] = {}
    airlockArgs["store"] = EgressStore(Path(filestore))
    airlockArgs["admin_group"] = admin_group
    airlockArgs["user_store"] = UserEgressStore(Path(user_store))
    airlockArgs["baseurl"] = JUPYTERHUB_SERVICE_PREFIX

    airlockArgs["jupyterhub_home"] = url_path_join(jupyterhub_url, "/hub/home")

    def rule(p: str, handler: type[RequestHandler], *args: Any, **kwargs: Any) -> url:
        return url(
            url_path_join(JUPYTERHUB_SERVICE_PREFIX, p), handler, *args, **kwargs
        )

    # https://www.tornadoweb.org/en/stable/web.html#tornado.web.URLSpec
    app = Application(
        [
            rule(r"/", AirlockHandler, airlockArgs, name="home"),
            rule(r"", RedirectHandler, {"url": JUPYTERHUB_SERVICE_PREFIX}),
            rule("oauth_callback", HubOAuthCallbackHandler),
            # TODO: Enforce naming restrictions on user and server names in JupyterHub
            rule(
                r"egress/(?P<group>[^/]+)/(?P<user>[^/]+)/(?P<egress>[^/]+)/?",
                AirlockEgressHandler,
                airlockArgs,
            ),
            rule(
                r"egress/(?P<group>[^/]+)/(?P<user>[^/]+)/(?P<egress>[^/]+)/download",
                AirlockDownloadHandler,
                airlockArgs,
            ),
            rule(
                r"new/?",
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
