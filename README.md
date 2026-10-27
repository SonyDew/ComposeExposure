# ComposeExposure

Static inspection of Docker Compose port publishing and host networking. No Docker daemon is required.

**Status:** In Development — Day 1 of SonyDev GitHub Marathon, October 27, 2026.

## Install

Requires Python 3.10 or later.

```sh
python -m pip install .
```

## Usage

```sh
compose-exposure scan compose.yaml
compose-exposure scan compose.yaml --format json
compose-exposure scan compose.yaml --fail-on all
compose-exposure compare compose.yaml compose.production.yaml
compose-exposure compare compose.yaml compose.production.yaml --fail-on nonlocal
```

`scan` lists published ports and services using host networking. It labels bindings as `all` (all interfaces), `loopback` (local only), `specific` (a non-loopback IP), or `unknown` (unresolved or unrecognized host binding). Host networking is labeled `host`. Ports with no fixed published host port are shown as `dynamic`. Entries under `expose` are not host-published ports and are omitted.

`compare` reports added and removed exposure records. It does not infer whether a change is safe. `--fail-on all` returns exit code 1 for all-interface bindings or host networking; `--fail-on nonlocal` also includes specific and unknown bindings. In comparisons, only added records are evaluated by `--fail-on`.

Exit codes: `0` success, `1` selected exposure found, `2` invalid or unreadable input.

## Limitations

This is a static per-file audit, not an evaluation of the effective Docker Compose configuration. It does not merge multiple `-f` files, resolve `extends` or `include`, interpolate environment variables, select profiles, or inspect firewalls, Docker networks, and running containers. A specific IP binding may still be reachable from other machines. Unknown bindings require manual review. YAML custom tags such as `!reset` are not supported.

## Tests

```sh
python -m unittest discover -s tests -v
```
