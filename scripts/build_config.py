#!/usr/bin/env python3
"""Build the personal Shadowrocket config from the latest upstream lazy config.

Upstream remains responsible for general compatibility defaults, documentation,
Host, URL Rewrite and MITM sections. The personal policy template owns DNS
privacy, IPv6, proxy groups and routing rules so upstream updates cannot silently
replace those decisions.
"""

from __future__ import annotations

import argparse
import os
import re
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


UPSTREAM_URL = (
    "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/"
    "lazy_group.conf"
)

MANAGED_GENERAL_KEYS = {
    "dns-server",
    "direct-dns-server",
    "fallback-dns-server",
    "dns-fallback-system",
    "ipv6",
    "prefer-ipv6",
    "dns-direct-system",
    "dns-direct-fallback-proxy",
    "hijack-dns",
    "udp-policy-not-supported-behaviour",
    "block-quic",
    "update-url",
}


@dataclass
class Config:
    preamble: list[str]
    order: list[str]
    sections: dict[str, list[str]]


def parse_config(text: str) -> Config:
    preamble: list[str] = []
    order: list[str] = []
    sections: dict[str, list[str]] = {}
    current: str | None = None

    for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        match = re.fullmatch(r"\s*\[([^]]+)]\s*", line)
        if match:
            current = match.group(1)
            if current in sections:
                raise ValueError(f"duplicate section: [{current}]")
            order.append(current)
            sections[current] = []
        elif current is None:
            preamble.append(line)
        else:
            sections[current].append(line)

    return Config(preamble, order, sections)


def active_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    return key.strip(), value.strip()


def active_values(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        assignment = active_assignment(line)
        if assignment:
            key, value = assignment
            if key in values:
                raise ValueError(f"duplicate active setting: {key}")
            values[key] = value
    return values


def merge_general(upstream: list[str], policy: list[str]) -> list[str]:
    policy_values = active_values(policy)
    missing = (MANAGED_GENERAL_KEYS - {"direct-dns-server"}) - policy_values.keys()
    if missing:
        raise ValueError(f"policy is missing managed General settings: {sorted(missing)}")
    if "direct-dns-server" in policy_values:
        raise ValueError("direct-dns-server must stay unset; direct traffic uses system DNS")

    output: list[str] = []
    emitted: set[str] = set()
    for line in upstream:
        assignment = active_assignment(line)
        if not assignment:
            output.append(line)
            continue
        key, _ = assignment
        if key not in MANAGED_GENERAL_KEYS:
            output.append(line)
            continue
        if key in policy_values and key not in emitted:
            output.append(f"{key} = {policy_values[key]}")
            emitted.add(key)

    remaining = [
        key
        for key in MANAGED_GENERAL_KEYS
        if key in policy_values and key not in emitted
    ]
    if remaining:
        output.extend(["", "# Personal privacy and routing settings"])
        for key in sorted(remaining):
            output.append(f"{key} = {policy_values[key]}")
    return output


def render(config: Config) -> str:
    lines = list(config.preamble)
    for section in config.order:
        lines.append(f"[{section}]")
        lines.extend(config.sections[section])
    return "\n".join(lines).rstrip() + "\n"


def fetch_text(source: str) -> str:
    if source.startswith(("https://", "http://")):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "shadowrocket-config-builder/1.0"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8-sig")
    return Path(source).read_text(encoding="utf-8-sig")


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=UPSTREAM_URL)
    parser.add_argument("--policy", default="config/policy.conf")
    parser.add_argument("--output", default="output/Shadowrocket-Pro.conf")
    args = parser.parse_args()

    upstream = parse_config(fetch_text(args.source))
    policy = parse_config(fetch_text(args.policy))
    required = {"General", "Proxy Group", "Rule", "Host", "URL Rewrite", "MITM"}
    for label, config in (("upstream", upstream), ("policy", policy)):
        missing = required - config.sections.keys()
        if missing:
            raise ValueError(f"{label} config is missing sections: {sorted(missing)}")

    upstream.sections["General"] = merge_general(
        upstream.sections["General"], policy.sections["General"]
    )
    upstream.sections["Proxy Group"] = list(policy.sections["Proxy Group"])
    upstream.sections["Rule"] = list(policy.sections["Rule"])

    output_path = Path(args.output)
    atomic_write(output_path, render(upstream))
    print(f"built {output_path}")


if __name__ == "__main__":
    main()
