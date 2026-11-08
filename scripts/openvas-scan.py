"""Scan only the fixed internal Apache target in the SOC-OpenVAS lab."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import time
import xml.etree.ElementTree as ET


TARGET_IP = "172.31.250.10"
TARGET_NAME = "SOC lab Apache 80 only"
PORT_LIST_NAME = "SOC lab TCP 80 only"
SOCKET = "/var/lib/docker/volumes/soc-openvas_gvmd_socket_vol/_data/gvmd.sock"
PASSWORD = Path("/opt/soc-openvas/.gmp-password")


def xml(parent, tag, text=None, **attributes):
    node = ET.SubElement(parent, tag, attributes)
    node.text = text
    return node


class Manager:
    def __enter__(self):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(90)
        self.connection.connect(SOCKET)
        request = ET.Element("authenticate")
        credentials = xml(request, "credentials")
        xml(credentials, "username", "admin")
        xml(credentials, "password", PASSWORD.read_text().strip())
        self.request(request)
        return self

    def __exit__(self, *_):
        self.connection.close()

    def request(self, request):
        self.connection.sendall(ET.tostring(request, encoding="utf-8"))
        parser = ET.XMLPullParser(events=("start", "end"))
        depth = 0
        while True:
            data = self.connection.recv(65536)
            if not data:
                raise RuntimeError("Greenbone closed the socket before sending a complete reply")
            parser.feed(data)
            for event, node in parser.read_events():
                depth += 1 if event == "start" else -1
                if depth == 0:
                    status = node.get("status", "")
                    if not status.startswith("2"):
                        raise RuntimeError(f"{request.tag}: {status} {node.get('status_text', '')}")
                    return node

    def named(self, endpoint, element, name):
        response = self.request(ET.Element(endpoint, {"filter": "rows=-1"}))
        return next((item for item in response.findall(element) if item.findtext("name") == name), None)


def ensure_target(gmp):
    existing = gmp.named("get_targets", "target", TARGET_NAME)
    if existing is not None:
        if existing.findtext("hosts") != TARGET_IP:
            raise RuntimeError("Existing target name points to an unexpected address")
        return existing.get("id")

    ports = gmp.named("get_port_lists", "port_list", PORT_LIST_NAME)
    if ports is None:
        request = ET.Element("create_port_list")
        xml(request, "name", PORT_LIST_NAME)
        xml(request, "port_range", "T:80")
        port_id = gmp.request(request).get("id")
    else:
        port_id = ports.get("id")

    request = ET.Element("create_target")
    xml(request, "name", TARGET_NAME)
    xml(request, "hosts", TARGET_IP)
    xml(request, "port_list", id=port_id)
    xml(request, "alive_tests", "Consider Alive")
    return gmp.request(request).get("id")


def scan(gmp, phase):
    config = gmp.named("get_configs", "config", "Full and fast")
    scanner = gmp.named("get_scanners", "scanner", "OpenVAS Default")
    if config is None or scanner is None:
        raise RuntimeError("The scanner or scan configuration is still importing its feed")

    request = ET.Element("create_task")
    xml(request, "name", f"SOC lab Apache {phase} {datetime.now(timezone.utc):%Y%m%d-%H%M%S}")
    xml(request, "target", id=ensure_target(gmp))
    xml(request, "config", id=config.get("id"))
    xml(request, "scanner", id=scanner.get("id"))
    task = gmp.request(request).get("id")
    report = gmp.request(ET.Element("start_task", {"task_id": task})).findtext("report_id")
    print(f"Started {phase} scan. Task {task}", flush=True)

    deadline = time.monotonic() + 1200
    previous = None
    while time.monotonic() < deadline:
        state = gmp.request(ET.Element("get_tasks", {"task_id": task})).find("task")
        status = state.findtext("status")
        progress = state.findtext("progress")
        if (status, progress) != previous:
            print(f"{phase}: {status} ({progress}%)", flush=True)
            previous = (status, progress)
        if status == "Done":
            break
        if status in {"Stopped", "Interrupted", "Internal Error"}:
            raise RuntimeError(f"Scan ended with status {status}")
        time.sleep(10)
    else:
        gmp.request(ET.Element("stop_task", {"task_id": task}))
        raise TimeoutError("The scan exceeded 20 minutes and was stopped")

    response = gmp.request(ET.Element("get_reports", {
        "report_id": report, "details": "1", "ignore_pagination": "1",
        "filter": "rows=-1 levels=hmlg min_qod=0",
    }))
    findings = []
    for item in response.findall(".//results/result"):
        findings.append({
            "name": item.findtext("name"),
            "severity": item.findtext("severity"),
            "qod": item.findtext("qod/value"),
            "port": item.findtext("port"),
            "references": [node.get("id") for node in item.findall("nvt/refs/ref")
                           if node.get("type") == "cve"],
        })
    return {"phase": phase, "report_id": report, "target": "isolated Apache container",
            "finished_utc": datetime.now(timezone.utc).isoformat(), "findings": findings}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("baseline", "patched", "hardened"))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with Manager() as manager:
        evidence = scan(manager, args.phase)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(evidence['findings'])} results to {args.output.name}", flush=True)
