#!/usr/bin/env python3
"""Fail closed when a generated Shadowrocket configuration is inconsistent."""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import sys
import urllib.request
from pathlib import Path


EXPECTED_GENERAL = {
    "dns-server": "https://cloudflare-dns.com/dns-query#proxy",
    "fallback-dns-server": "https://dns.google/dns-query#proxy",
    "dns-fallback-system": "false",
    "ipv6": "true",
    "prefer-ipv6": "false",
    "dns-direct-system": "true",
    "dns-direct-fallback-proxy": "false",
    "update-url": (
        "https://raw.githubusercontent.com/wxk40899-sys/shadowrocket-config/"
        "main/output/Shadowrocket-Pro.conf"
    ),
}

REQUIRED_GROUPS = {
    "🚀 节点选择",
    "🧱 DNS 防泄露",
    "🏠 私有网络",
    "🔒 国内服务",
    "🌍 非中国",
    "🐱 代码托管",
    "🐟 漏网之鱼",
    "AI",
    "YouTube",
    "Netflix",
    "TikTok",
}

BUILTINS = {"PROXY", "DIRECT", "REJECT", "REJECT-NO-DROP"}
BANNED_ACTIVE_TERMS = {"ZOUTER", "DATAWAVE", "LOCAL-SERVERS", "银行", "券商", "证券"}


def parse_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        match = re.fullmatch(r"\s*\[([^]]+)]\s*", line)
        if match:
            current = match.group(1)
            if current in sections:
                raise ValueError(f"duplicate section [{current}]")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return sections


def active(lines: list[str]) -> list[str]:
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    ]


def assignments(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in active(lines):
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in values:
            raise ValueError(f"duplicate setting or group: {key}")
        values[key] = value
    return values


def validate_group_references(groups: dict[str, str]) -> list[str]:
    errors: list[str] = []
    known = set(groups) | BUILTINS
    for name, expression in groups.items():
        fields = [field.strip() for field in expression.split(",")]
        if not fields or fields[0] not in {
            "select", "url-test", "fallback", "load-balance", "random"
        }:
            errors.append(f"group {name!r} has an unsupported type")
            continue
        for field in fields[1:]:
            if not field or "=" in field:
                if field.startswith("policy-select-name="):
                    target = field.split("=", 1)[1]
                    if target not in known:
                        errors.append(
                            f"group {name!r} selects undefined policy {target!r}"
                        )
                continue
            if field not in known:
                errors.append(
                    f"group {name!r} contains a concrete or undefined policy {field!r}"
                )
    return errors


def rule_policy(rule: str) -> str | None:
    fields = [field.strip() for field in rule.split(",")]
    if fields[0] == "FINAL":
        return fields[1] if len(fields) > 1 else None
    if fields[0] in {"AND", "OR", "NOT"}:
        return fields[-1] if len(fields) > 1 else None
    return fields[2] if len(fields) > 2 else None


def check_url(url: str) -> tuple[str, str | None]:
    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "shadowrocket-config-validator/1.0",
                "Range": "bytes=0-63",
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(64)
        return url, None
    except Exception as exc:  # network errors must block publication
        return url, str(exc)


def validate(path: Path, check_urls: bool) -> None:
    text = path.read_text(encoding="utf-8-sig")
    sections = parse_sections(text)
    errors: list[str] = []
    required_sections = {"General", "Proxy Group", "Rule"}
    if missing := required_sections - sections.keys():
        errors.append(f"missing sections: {sorted(missing)}")
        raise ValueError("; ".join(errors))

    general = assignments(sections["General"])
    for key, expected in EXPECTED_GENERAL.items():
        if general.get(key) != expected:
            errors.append(f"{key} must be {expected!r}, got {general.get(key)!r}")
    if "direct-dns-server" in general:
        errors.append("direct-dns-server must be absent; direct traffic uses system DNS")

    groups = assignments(sections["Proxy Group"])
    if missing := REQUIRED_GROUPS - groups.keys():
        errors.append(f"missing required groups: {sorted(missing)}")
    errors.extend(validate_group_references(groups))

    rules = active(sections["Rule"])
    known_policies = set(groups) | BUILTINS
    for rule in rules:
        for term in BANNED_ACTIVE_TERMS:
            if term in rule:
                errors.append(f"banned active term {term!r}: {rule}")
        policy = rule_policy(rule)
        if not policy:
            errors.append(f"cannot parse rule policy: {rule}")
        elif policy not in known_policies:
            errors.append(f"rule references undefined policy {policy!r}: {rule}")

    final_rules = [rule for rule in rules if rule.startswith("FINAL,")]
    if final_rules != ["FINAL,🐟 漏网之鱼"]:
        errors.append(f"unexpected FINAL rules: {final_rules}")
    if not rules or rules[-1] != "FINAL,🐟 漏网之鱼":
        errors.append("FINAL must be the last active rule")
    if "QuantumultX/" in "\n".join(rules):
        errors.append("QuantumultX rule sources are not allowed in this Shadowrocket config")

    block_indexes = [i for i, rule in enumerate(rules) if "BlockHttpDNS" in rule]
    broad_indexes = [
        i for i, rule in enumerate(rules) if "/China/China.list" in rule or "/Global/Global.list" in rule
    ]
    if len(block_indexes) != 1 or not broad_indexes or block_indexes[0] > min(broad_indexes):
        errors.append("BlockHttpDNS must appear once before broad China/Global rules")

    for term in BANNED_ACTIVE_TERMS:
        for name, expression in groups.items():
            if term in name or term in expression:
                errors.append(f"banned group term {term!r}: {name} = {expression}")

    if check_urls:
        urls = sorted(
            {
                fields[1]
                for rule in rules
                if (fields := [part.strip() for part in rule.split(",")])
                and fields[0] == "RULE-SET"
                and len(fields) > 2
                and fields[1].startswith("https://")
            }
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            for url, failure in executor.map(check_url, urls):
                if failure:
                    errors.append(f"unreachable rule URL {url}: {failure}")

    if errors:
        raise ValueError("\n".join(f"- {error}" for error in errors))
    print(
        f"validated {path}: {len(groups)} groups, {len(rules)} active rules, "
        f"IPv6 enabled, direct DNS=system, proxy DNS=encrypted"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default="output/Shadowrocket-Pro.conf")
    parser.add_argument("--check-urls", action="store_true")
    args = parser.parse_args()
    try:
        validate(Path(args.path), args.check_urls)
    except Exception as exc:
        print(f"validation failed:\n{exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
