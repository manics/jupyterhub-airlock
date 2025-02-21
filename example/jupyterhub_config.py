# Configuration file for jupyterhub
# Uses Dummy authenticator and Simple spawner
import sys
from pathlib import Path

c = get_config()  # noqa
# c.Application.log_level = 'DEBUG'

c.JupyterHub.authenticator_class = "dummy"
c.JupyterHub.spawner_class = "simple"

user_dir = Path(__file__).parent / "users"
user_dir.mkdir(exist_ok=True)
c.SimpleLocalProcessSpawner.home_dir_template = f"{user_dir}/{{username}}"
c.SimpleLocalProcessSpawner.pre_spawn_hook = lambda spawner: (
    user_dir / spawner.user.name / "egress"
).mkdir(parents=True, exist_ok=True)

c.Authenticator.admin_users = {"admin", "demo"}

# c.JupyterHub.allow_named_servers = True
# c.JupyterHub.named_server_limit_per_user = 2
# c.Spawner.disable_user_config = True


c.JupyterHub.services = [
    {
        "name": "airlock",
        "url": "http://127.0.0.1:10112",
        "command": [
            sys.executable,
            "-mjupyterhub_airlock.airlock",
            # "jupyterhub-airlock",
            "--filestore",
            "egress-store",
            "--debug",
            "--userstore",
            str(user_dir),
        ],
        "environment": {"PYTHONPATH": ".."},
        "oauth_no_confirm": True,
    },
]

c.JupyterHub.load_groups = {"egress-admins": {"users": ["admin"]}}


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
    {
        "name": "airlock",
        "scopes": [
            "read:users",
            "read:servers",
            "admin:server_state",
        ],
        "services": ["airlock"],
    },
]

# Don't automatically go to server, easier to test hub
c.JupyterHub.default_url = "/hub/home"
