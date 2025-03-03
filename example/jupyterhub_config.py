# Configuration file for jupyterhub
# Uses Dummy authenticator and Simple spawner
import sys
from pathlib import Path

from jupyterhub.spawner import SimpleLocalProcessSpawner
from tornado.web import HTTPError
from traitlets import Dict, List, Tuple, Unicode, default

c = get_config()  # noqa
# c.Application.log_level = 'DEBUG'

c.JupyterHub.bind_url = "http://localhost:8000"

c.JupyterHub.authenticator_class = "dummy"
# c.JupyterHub.spawner_class = "simple"

# Spawner group (project) profiles
USER_DIR = Path(__file__).parent / "users"
USER_DIR.mkdir(exist_ok=True)


class GroupProfileSpawner(SimpleLocalProcessSpawner):
    profiles = Dict(
        Unicode(),
        default_value={},
        config=True,
    )

    @default("profiles")
    def _default_profiles(self):
        groups = self.user.groups
        return dict((group.name, group.name) for group in groups)

    @default("options_form")
    def _default_options_form(self):
        options = []
        if len(self.profiles) < 1:
            raise HTTPError(403, "No valid groups found")
        # Don't select a default if multiple groups available
        template = """
            <label class="form-control">
            <input type="radio" name="profile" value="{key}" required {checked}/>
            {display}
            </label>
            """
        if len(self.profiles) == 1:
            checked = "checked"
        else:
            checked = ""
        options = [
            template.format(key=key, display=display, checked=checked)
            for key, display in self.profiles.items()
        ]
        return "<h2>Select a project</h2>\n" + "\n".join(options)

    def options_from_form(self, formdata):
        profile = formdata.get("profile")
        if profile:
            profile = profile[0]
        if not profile:
            raise HTTPError(400, "No profile provided")
        return dict(profile=profile)
        # Validation is done in start() since parameters may be provided by
        # REST API instead of this form

    def _update_from_profile(self):
        profile = self.user_options.get("profile")
        if not profile or profile not in self.profiles:
            raise HTTPError(400, "Invalid profile")

        username = self.user.name

        if profile == "egress-admin":
            self.home_dir = f"{USER_DIR}"
        else:
            self.home_dir = f"{USER_DIR}/{profile}/{username}"
        return profile

    async def start(self):
        self._update_from_profile()
        return await super().start()


# c.SimpleLocalProcessSpawner.home_dir_template = f"{user_dir}/{{username}}"
c.JupyterHub.spawner_class = GroupProfileSpawner

c.Authenticator.admin_users = {"admin", "demo"}

# c.JupyterHub.allow_named_servers = True
# c.JupyterHub.named_server_limit_per_user = 2
# c.Spawner.disable_user_config = True


c.JupyterHub.services = [
    {
        "name": "airlock",
        # "api_token": "Needed if running as external service (doubles as client secret)"
        "url": "http://127.0.0.1:10112",
        "command": [
            sys.executable,
            "-mjupyterhub_airlock.main",
            "--filestore",
            "egress-store",
            "--debug",
            "--userstore",
            # Typically you'd have a separate filesystem, and mount subdirectories
            # into a users homedir. For demo treat the entire homedir as available
            str(USER_DIR),
        ],
        "environment": {"PYTHONPATH": ".."},
        "oauth_no_confirm": True,
    },
]

c.JupyterHub.load_groups = {
    "project-1": {"users": ["user-1", "user-2"]},
    "project-2": {"users": ["user-2"]},
    "egress-admins": {"users": ["admin"]},
}


c.JupyterHub.load_roles = [
    {
        "name": "admin",
        "users": ["demo"],
    },
    {
        "name": "user",
        # grant all users access to all services
        "scopes": ["access:services", "self"],
    },
    # {
    #     "name": "airlock",
    #     "scopes": [
    #         "read:users",
    #         "read:servers",
    #         "admin:server_state",
    #     ],
    #     "services": ["airlock"],
    # },
]

# Don't automatically go to server, easier to test hub
c.JupyterHub.default_url = "/hub/home"
