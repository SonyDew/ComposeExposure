"""Static inspection of Docker Compose port publishing and host networking."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


class ComposeError(ValueError):
    """A Compose file cannot be inspected reliably."""


class StrictLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping(loader: StrictLoader, node: yaml.MappingNode) -> dict:
    # Reject repeated explicit keys, but allow explicit overrides of YAML merges.
    explicit: set = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=True)
        try:
            if key in explicit:
                raise ComposeError("Duplicate YAML key")
            explicit.add(key)
        except TypeError as exc:
            raise ComposeError("YAML mapping keys must be hashable") from exc
    loader.flatten_mapping(node)
    result: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        result[key] = loader.construct_object(value_node, deep=True)
    return result


# Compose uses YAML 1.2 scalar rules. PyYAML defaults to YAML 1.1, where
# "on" becomes True and unquoted "1:20" becomes the integer 80.
StrictLoader.yaml_implicit_resolvers = {
    first: [item for item in resolvers if item[0] not in (
        "tag:yaml.org,2002:bool", "tag:yaml.org,2002:int"
    )]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int",
    re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"),
    list("-+0123456789"),
)
StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True, order=True)
class Exposure:
    service: str
    kind: str
    bind: str
    published: str
    target: str
    protocol: str
    scope: str
    mode: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


_INTERPOLATION = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
_PORT_NUMBER = re.compile(r"^[0-9]+(?:-[0-9]+)?$")


def _split_short(value: str) -> list[str]:
    """Split colons outside IPv6 brackets and Compose substitutions."""
    parts: list[str] = []
    buf: list[str] = []
    bracket = 0
    substitution = 0
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "$" and value[i : i + 2] == "${":
            substitution += 1
            buf.append("${")
            i += 2
            continue
        if ch == "}" and substitution:
            substitution -= 1
        elif not substitution:
            if ch == "[":
                bracket += 1
            elif ch == "]":
                bracket -= 1
                if bracket < 0:
                    raise ComposeError("Invalid bracket in port")
            elif ch == ":" and bracket == 0:
                parts.append("".join(buf))
                buf.clear()
                i += 1
                continue
        buf.append(ch)
        i += 1
    if bracket or substitution:
        raise ComposeError("Unclosed bracket or substitution in port")
    parts.append("".join(buf))
    if len(parts) > 3:
        raise ComposeError("Invalid short port syntax")
    return parts


def _validate_port(value: str, *, allow_empty: bool = False) -> str:
    if not value and allow_empty:
        return "dynamic"
    if _INTERPOLATION.search(value):
        return value
    if not _PORT_NUMBER.fullmatch(value):
        raise ComposeError("Invalid port number or range")
    digits = [part.lstrip("0") or "0" for part in value.split("-")]
    if any(len(part) > 5 for part in digits):
        raise ComposeError("Port outside 1–65535")
    bounds = [int(part) for part in digits]
    if any(p < 1 or p > 65535 for p in bounds) or bounds[-1] < bounds[0]:
        raise ComposeError("Port outside 1–65535 or reversed range")
    return "-".join(str(p) for p in bounds)


def _normalize_bind(bind: str) -> str:
    if "[" in bind or "]" in bind:
        if not (bind.startswith("[") and bind.endswith("]")
                and bind.count("[") == 1 and bind.count("]") == 1):
            raise ComposeError("Invalid brackets in host binding")
        return bind[1:-1]
    return bind


def _scope(bind: str) -> str:
    if bind == "*":
        return "all"
    if _INTERPOLATION.search(bind):
        return "unknown"
    try:
        addr = ipaddress.ip_address(bind)
    except ValueError:
        return "unknown"
    if addr.is_unspecified:
        return "all"
    return "loopback" if addr.is_loopback else "specific"


def _port_record(service: str, entry: Any) -> Exposure:
    if isinstance(entry, bool):
        raise ComposeError(f"Service {service!r}: boolean port is invalid")
    if isinstance(entry, (str, int)):
        raw = str(entry).strip()
        proto = "tcp"
        if "/" in raw:
            raw, proto = raw.rsplit("/", 1)
            if not proto:
                raise ComposeError(f"Service {service!r}: missing protocol")
        parts = _split_short(raw)
        if len(parts) == 1:
            bind, published, target = "*", "dynamic", parts[0]
        elif len(parts) == 2:
            bind, published, target = "*", parts[0], parts[1]
        else:
            bind, published, target = parts
            if not bind:
                bind = "*"
            bind = _normalize_bind(bind)
        target = _validate_port(target)
        published = _validate_port(published, allow_empty=True) if published != "dynamic" else published
        mode = ""
    elif isinstance(entry, dict):
        if "target" not in entry:
            raise ComposeError(f"Service {service!r}: long port entry needs target")
        bind_value = entry.get("host_ip")
        if bind_value is not None and not isinstance(bind_value, str):
            raise ComposeError("Long port host_ip must be a string")
        bind = _normalize_bind(bind_value) if bind_value is not None else "*"
        published_value = entry.get("published")
        published = (
            _validate_port(str(published_value)) if published_value is not None else "dynamic"
        )
        target = _validate_port(str(entry["target"]))
        proto = str(entry.get("protocol", "tcp"))
        mode = str(entry.get("mode", ""))
    else:
        raise ComposeError(f"Service {service!r}: unsupported port entry")
    if proto not in ("tcp", "udp", "sctp") and not _INTERPOLATION.search(proto):
        raise ComposeError(f"Service {service!r}: invalid protocol")
    return Exposure(service, "port", bind, published, target, proto, _scope(bind), mode)


def inspect(path: str | Path) -> list[Exposure]:
    """Read one file without applying Compose overrides or environment variables."""
    source = Path(path)
    try:
        doc = yaml.load(source.read_text(encoding="utf-8"), Loader=StrictLoader)
    except ComposeError:
        raise
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ComposeError(f"{source}: invalid YAML{location}") from exc
    except ValueError as exc:
        raise ComposeError(f"{source}: invalid YAML scalar") from exc
    except (OSError, UnicodeError) as exc:
        raise ComposeError(f"Cannot read {source}: {exc.strerror if isinstance(exc, OSError) else 'invalid text encoding'}") from exc
    if not isinstance(doc, dict):
        raise ComposeError(f"{source}: expected a YAML mapping")
    services = doc.get("services")
    if not isinstance(services, dict):
        raise ComposeError(f"{source}: expected a services mapping")
    records: set[Exposure] = set()
    for name, config in services.items():
        if not isinstance(name, str) or not isinstance(config, dict):
            raise ComposeError(f"{source}: invalid service definition: {name!r}")
        network_mode = config.get("network_mode")
        if network_mode is not None and not isinstance(network_mode, str):
            raise ComposeError(f"{source}: service {name!r} network_mode must be a string")
        if network_mode == "host":
            records.add(Exposure(name, "host-network", "host", "", "", "", "host", ""))
        elif network_mode and _INTERPOLATION.search(network_mode):
            records.add(Exposure(name, "network-mode-unknown", network_mode, "", "", "", "unknown", ""))
        ports = config.get("ports", [])
        if ports is None:
            ports = []
        if not isinstance(ports, list):
            raise ComposeError(f"{source}: service {name!r} ports must be a list")
        for port in ports:
            try:
                records.add(_port_record(name, port))
            except ComposeError as exc:
                raise ComposeError(f"{source}: {exc}") from exc
    return sorted(records)


def compare(baseline: list[Exposure], candidate: list[Exposure]) -> dict[str, list[Exposure]]:
    return {
        "added": sorted(set(candidate) - set(baseline)),
        "removed": sorted(set(baseline) - set(candidate)),
    }


def risky(records: list[Exposure], threshold: str) -> bool:
    if threshold == "all":
        return any(record.scope in ("all", "host") for record in records)
    if threshold == "nonlocal":
        return any(record.scope != "loopback" for record in records)
    raise ValueError(f"Unsupported threshold: {threshold}")
