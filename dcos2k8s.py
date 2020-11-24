#!/usr/bin/env python
import requests
import json
import subprocess
import logging
import sys
from typing import List
from argparse import ArgumentParser
from pprint import pprint


log_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.WARN, format=log_format)
logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger(__name__)


def main() -> None:
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    dcos = DCOS(args.dcos_cmd)
    app = dcos.app(args.app)
    pprint(app)


class DCOS:
    def __init__(self, cmd: str):
        self.cmd = cmd
        self.url = None
        self.token = None
        self.load_cluster_details()

    def load_cluster_details(self):
        url, token = get_cluster_details(self.cmd)
        self.url = url.strip("/")
        self.token = token

    def fetch(self, suffix: str) -> str:
        headers = {"Authorization": f"token={self.token}"}
        url = f"{self.url}/{suffix}"
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            log.critical(f"Fatal error retrieving {url}")
            sys.exit(1)
        return r.json()

    def app(self, name: str):
        keep = [
            "container",
            "env",
            "cpus",
            "gpus",
            "disk",
            "fetch",
            "healthChecks",
            "id",
            "instances",
            "labels",
            "mem",
            "networks",
            "secrets",
            "upgradeStrategy",
        ]
        app_url = f"service/marathon/v2/apps/{name}"
        log.info(f"Fetching app {name}")
        app = self.fetch(app_url).get("app")
        for secret, source in app.get("secrets", {}).items():
            if not isinstance(source, dict):
                continue
            source = source.get("source")
            if not source:
                continue
            secret_data = self.secret(source)
            app["secrets"][secret] = secret_data
        for key in list(app.keys()):
            if key not in keep:
                del app[key]
        return app

    def secret(self, name: str):
        secret_url = f"secrets/v1/secret/default/{name}"
        log.debug(f"Fetching secret {name}")
        secret = self.fetch(secret_url).get("value")
        return secret


def get_cluster_details(dcos_cmd: str) -> List:
    url = token = None

    dcos_token_args = ["config", "show", "core.dcos_acs_token"]
    dcos_baseurl_args = ["config", "show", "core.dcos_url"]

    cmd = [dcos_cmd] + dcos_token_args
    token = run_cmd(cmd, "retrieve DC/OS auth token")

    cmd = [dcos_cmd] + dcos_baseurl_args
    url = run_cmd(cmd, "retrieve DC/OS cluster URL")

    return url, token


def run_cmd(cmd: str, purpose: str) -> str:
    cmd_str = " ".join(cmd)
    log.debug(f"Running command `{cmd_str}` to {purpose}")
    res = subprocess.run(cmd, capture_output=True)
    if res.returncode != 0:
        err = res.stderr.decode("utf-8").strip()
        log.critical(f"Failed to {purpose}: {err}")
        sys.exit(1)
    return res.stdout.decode("utf-8").strip()


def get_arg_parser() -> ArgumentParser:
    arg_parser = ArgumentParser(description="DC/OS to Kubernetes converter")
    arg_parser.add_argument(
        "--verbose",
        "-v",
        help="Verbose logging",
        dest="verbose",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument(
        "--app",
        help="Name of the DC/OS App to migrate (e.g. cloudkeeper/gcp)",
        default=None,
        required=True,
        dest="app",
        type=str,
    )
    arg_parser.add_argument(
        "--dcos",
        help="Name of the DC/OS cli binary (default: dcos)",
        default="dcos",
        dest="dcos_cmd",
        type=str,
    )
    return arg_parser


if __name__ == "__main__":
    main()
