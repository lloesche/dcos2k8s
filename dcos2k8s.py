#!/usr/bin/env python
import requests
import yaml
import base64
import subprocess
import logging
import sys
from typing import List, Dict
from argparse import ArgumentParser
from pprint import pformat


log_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.WARN, format=log_format)
logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger(__name__)


def main() -> None:
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    dcos = DCOS()
    dcos_app = dcos.app(args.app)
    output = open(args.out, "w") if args.out else sys.stdout
    try:
        dcos2k8s(dcos_app, output, args)
    finally:
        if output is not sys.stdout:
            output.close()


def dcos2k8s(app: Dict, output, args):
    name = app.get("id").strip("/").replace("/", "-")
    image = app.get("container", {}).get("docker", {}).get("image")
    #labels = app.get("labels", {})
    #for label, label_data in labels.items():
    #    if not str(label).startswith("HAPROXY_"):
    #        continue
    #    _, idx, action = label.split("_", 2)

    k8s_deployment = get_k8s_definition(
        ["create", "deployment", f"--image={image}", name]
    )
    if "cmd" in app and len(app["cmd"]) > 0:
        cmd = app.get("cmd", "").split(" ")
        k8s_deployment["spec"]["template"]["spec"]["containers"][0]["command"] = cmd

    port_mappings = app.get("container", {}).get("portMappings", [])
    k8s_service = None
    if len(port_mappings) > 0:
        ensure_list(
            "ports", k8s_deployment["spec"]["template"]["spec"]["containers"][0]
        )
        k8s_service = {
            "kind": "Service",
            "apiVersion": "v1",
            "metadata": {
                "name": name,
                "creationTimestamp": None,
                "labels": {"app": name},
            },
            "spec": {
                "ports": [],
                "selector": {"app": name},
            },
            "status": {"loadBalancer": {}},
        }
    for port_mapping in port_mappings:
        port = port_mapping.get("containerPort")
        name = port_mapping.get("name")
        protocol = port_mapping.get("protocol", "tcp")
        if not port:
            continue
        port_spec = {"containerPort": port}
        if name:
            port_spec["name"] = name
        k8s_deployment["spec"]["template"]["spec"]["containers"][0]["ports"].append(
            port_spec
        )
        k8s_service["spec"]["ports"].append(
            {"protocol": str(protocol).upper(), "port": port, "targetPort": port}
        )

    if args.limit_resources or args.reserve_resources:
        cpus = app.get("cpus", 0)
        disk = app.get("disk", 0)
        mem = app.get("mem", 0)
        gpu = app.get("gpu", 0)
        resources = {}
        if gpu > 0:
            gpu = int(gpu)
        if mem > 0:
            mem = f"{int(mem)}Mi"
            resources["memory"] = mem
        if cpus > 0:
            cpus = f"{int(cpus * 1000)}m"
            resources["cpu"] = cpus
        if disk > 0:
            resources["ephemeral-storage"] = f"{int(disk)}Gi"
        if len(resources) > 0:
            k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                "resources"
            ] = {}
            if args.limit_resources:
                k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                    "resources"
                ]["limits"] = dict(resources)
                # gpu are only allowed in limits not in requests (https://kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/)
                if gpu > 0:
                    k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                        "resources"
                    ]["limits"]["nvidia.com/gpu"] = gpu
            if args.reserve_resources:
                k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                    "resources"
                ]["requests"] = dict(resources)

    if "env" in app and len(app["env"]) > 0:
        k8s_deployment["spec"]["template"]["spec"]["containers"][0]["envFrom"] = [
            {"configMapRef": {"name": f"config-{name}"}}
        ]
        k8s_configmap_template = get_k8s_definition(
            ["create", "configmap", f"config-{name}"]
        )
        k8s_configmap_template["data"] = {}
        for var_name, var_data in app.get("env", {}).items():
            # secrets are handeled differently from config maps
            if isinstance(var_data, Dict) and "secret" in var_data:
                if (
                    not "env"
                    in k8s_deployment["spec"]["template"]["spec"]["containers"][0]
                ):
                    k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                        "env"
                    ] = []
                secret_data = {
                    "name": var_name,
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": f"secret-{name}",
                            "key": var_data["secret"],
                        }
                    },
                }
                k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                    "env"
                ].append(secret_data)
                continue

            k8s_configmap_template["data"][var_name] = var_data
        k8s_yaml = yaml.dump(k8s_configmap_template, Dumper=yaml.Dumper)
        output.write(k8s_yaml)
        output.write("---\n")

    if "fetch" in app and len(app["fetch"]) > 0:
        k8s_fileconfigmap_template = get_k8s_definition(
            ["create", "configmap", f"config-files-{name}"]
        )
        k8s_fileconfigmap_template["binaryData"] = {}
        for fetch_data in app.get("fetch", []):
            if "content" in fetch_data and "filename" in fetch_data:
                b64content = base64.b64encode(fetch_data["content"]).decode("utf-8")
                filename = fetch_data["filename"]
                k8s_fileconfigmap_template["binaryData"][filename] = b64content

        if len(k8s_fileconfigmap_template["binaryData"]) > 0:
            ensure_list(
                "volumeMounts",
                k8s_deployment["spec"]["template"]["spec"]["containers"][0],
            )
            ensure_list("volumes", k8s_deployment["spec"]["template"]["spec"])
            k8s_deployment["spec"]["template"]["spec"]["containers"][0][
                "volumeMounts"
            ].append(
                {
                    "name": "config-files",
                    "mountPath": "/mnt/mesos/sandbox",
                    "readOnly": True,
                }
            )
            k8s_deployment["spec"]["template"]["spec"]["volumes"].append(
                {
                    "name": "config-files",
                    "configMap": {"name": f"config-files-{name}", "items": []},
                }
            )

            for filename in k8s_fileconfigmap_template["binaryData"].keys():
                k8s_deployment["spec"]["template"]["spec"]["volumes"][0]["configMap"][
                    "items"
                ].append({"key": filename, "path": filename})

            k8s_yaml = yaml.dump(k8s_fileconfigmap_template, Dumper=yaml.Dumper)
            output.write(k8s_yaml)
            output.write("---\n")

    if "secrets" in app and len(app["secrets"]) > 0:
        k8s_secret_template = get_k8s_definition(
            ["create", "secret", "generic", f"secret-{name}"]
        )
        k8s_secret_template["data"] = {}
        for secret, secret_data in app.get("secrets", {}).items():
            k8s_secret_template["data"][secret] = base64.b64encode(
                secret_data.encode("utf-8")
            ).decode("utf-8")

        k8s_yaml = yaml.dump(k8s_secret_template, Dumper=yaml.Dumper)
        output.write(k8s_yaml)
        output.write("---\n")

    k8s_deployment["spec"]["replicas"] = app.get("instances", 1)
    k8s_yaml = yaml.dump(k8s_deployment, Dumper=yaml.Dumper)
    output.write(k8s_yaml)

    if k8s_service:
        output.write("---\n")
        k8s_yaml = yaml.dump(k8s_service, Dumper=yaml.Dumper)
        output.write(k8s_yaml)


def ensure_list(key, dst):
    if isinstance(dst, Dict) and key not in dst:
        dst[key] = []


def get_k8s_definition(args: List):
    cmd = ["kubectl", "--output=yaml", "--dry-run=client"] + args
    k8syaml = run_cmd(cmd, "get kubectl YAML")
    return yaml.load(k8syaml, Loader=yaml.Loader)


class DCOS:
    def __init__(self):
        self.url = None
        self.token = None
        self.load_cluster_details()

    def load_cluster_details(self):
        url, token = get_cluster_details()
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
            "cmd",
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
        log.debug(f"Fetching app {name}")
        app = self.fetch(app_url).get("app")
        for key in list(app.keys()):
            if key not in keep:
                del app[key]
        log.debug(f"App definition: {pformat(app)}")
        for secret, source in app.get("secrets", {}).items():
            if not isinstance(source, dict):
                continue
            source = source.get("source")
            if not source:
                continue
            secret_data = self.secret(source)
            app["secrets"][secret] = secret_data

        for fetch_data in app.get("fetch", []):
            uri = str(fetch_data.get("uri", ""))
            if not uri.startswith(("http://", "https://")):
                continue
            filename = uri.split("/")[-1]
            r = requests.get(uri, allow_redirects=True)
            if r.status_code == 200:
                fetch_data["content"] = r.content
                fetch_data["filename"] = filename

        return app

    def secret(self, name: str):
        secret_url = f"secrets/v1/secret/default/{name}"
        log.debug(f"Fetching secret {name}")
        secret = self.fetch(secret_url).get("value")
        return secret


def get_cluster_details() -> List:
    url = token = None

    dcos_token_args = ["config", "show", "core.dcos_acs_token"]
    dcos_baseurl_args = ["config", "show", "core.dcos_url"]

    cmd = ["dcos"] + dcos_token_args
    token = run_cmd(cmd, "retrieve DC/OS auth token")

    cmd = ["dcos"] + dcos_baseurl_args
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
        "--out",
        help="Name file to output generated yaml to (default: stdout)",
        default=None,
        required=False,
        dest="out",
        type=str,
    )
    arg_parser.add_argument(
        "--no-limit-resources",
        help="Don't limit resources (default: False)",
        dest="limit_resources",
        action="store_false",
        default=True,
    )
    arg_parser.add_argument(
        "--no-reserve-resources",
        help="Don't reserve resources (default: False)",
        dest="reserve_resources",
        action="store_false",
        default=True,
    )
    return arg_parser


if __name__ == "__main__":
    main()
