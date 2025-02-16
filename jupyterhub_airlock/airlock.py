#!/usr/bin/env python
"""
https://github.com/jupyterhub/jupyterhub/blob/5.0.0/examples/service-whoami/whoami-oauth.py
"""

from argparse import ArgumentParser, SUPPRESS
import json
import os
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application
from tornado.web import RequestHandler
from tornado.web import HTTPError
from tornado.web import authenticated
from tornado.web import url


from jupyterhub.services.auth import HubOAuthCallbackHandler
from jupyterhub.services.auth import HubOAuthenticated
from jupyterhub.utils import url_path_join

from .egress import EgressStore


import logging
from http.client import responses

log = logging.getLogger("jupyterhub_airlock")

# JUPYTERHUB_API_TOKEN = os.environ["JUPYTERHUB_API_TOKEN"]


class HomeNoSlashHandler(RequestHandler):
    def get(self) -> None:
        self.redirect(self.settings["baseurl"])


class AirlockHandler(HubOAuthenticated, RequestHandler):  # type: ignore[misc]
    def initialize(self, **kwargs: Any) -> None:
        self.store: EgressStore = kwargs.pop("store")
        if not self.store:
            raise ValueError("store required")
        super().initialize(**kwargs)

    def get_template_path(self) -> str:
        return os.path.join(os.path.dirname(__file__), "templates")

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

        egress_list = self.store.list()
        self.render(
            "index.html", username=username, groups=groups, egress_list=egress_list
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


class AirlockEgressHandler(AirlockHandler):
    @authenticated
    async def get(self, egress_id: str) -> None:
        egress = self.store.get_egress(egress_id)
        m = egress.metadata()
        self.render("egress.html", egress=m)


class HealthHandler(RequestHandler):
    async def get(self) -> None:
        self.set_header("content-type", "application/json")
        self.write(json.dumps({"status": "ok"}, indent=2, sort_keys=True))


def main(filestore: str, debug: bool = False) -> None:
    airlockArgs = {}
    airlockArgs["store"] = EgressStore(Path(filestore))

    JUPYTERHUB_SERVICE_PREFIX = os.getenv("JUPYTERHUB_SERVICE_PREFIX", "/")
    if not JUPYTERHUB_SERVICE_PREFIX.endswith("/"):
        JUPYTERHUB_SERVICE_PREFIX += "/"

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
            rule("/health/?", HealthHandler),
            # TODO: Enforce naming restrictions on user and server names in JupyterHub
            rule(r"/egress/(?P<egress_id>[^/]+)", AirlockEgressHandler, airlockArgs),
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
    main(args.filestore, args.debug)
