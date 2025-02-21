#!/usr/bin/env python
import logging
from argparse import SUPPRESS, ArgumentParser

from ._version import version
from .airlock import airlock


def main() -> None:
    log = logging.getLogger()

    parser = ArgumentParser("JupyterHub Airlock")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    parser.add_argument("--debug", action="store_true", help=SUPPRESS)
    parser.add_argument("--filestore", required=True, help="Egress filestore directory")
    parser.add_argument(
        "--userstore", required=True, help="User workspace egress filestore"
    )
    parser.add_argument(
        "--admin-group", default="egress-admins", help="Egress admin group"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {version}")
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
    airlock(args.filestore, args.userstore, args.admin_group, args.debug)


if __name__ == "__main__":
    main()
