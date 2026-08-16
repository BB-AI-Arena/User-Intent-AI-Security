from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request


def _request(server: str, token: str, path: str, method: str = "GET", body: object | None = None) -> dict:
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        server.rstrip("/") + path,
        data=payload,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error", exc.reason)
        except (json.JSONDecodeError, AttributeError):
            detail = exc.reason
        raise SystemExit(f"Intent Gate admin request failed: {detail}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uig-admin", description="Intent Gate network administration client")
    parser.add_argument("--server", default=os.environ.get("UIG_ADMIN_SERVER", "http://127.0.0.1:8787"))
    parser.add_argument("--token", default=os.environ.get("UIG_INGEST_TOKEN", ""))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("inventory", help="List discovered endpoints and security groups")
    sub.add_parser("discover", help="Create an enrolled-endpoint discovery session")
    deployments = sub.add_parser("deployments", help="List recent deployment waves")
    deployments.add_argument("--limit", type=int, default=20)
    deploy = sub.add_parser("deploy", help="Plan or queue the fixed Intent Gate deployment manifest")
    deploy.add_argument("--group", help="Target a security group")
    deploy.add_argument("--endpoint", action="append", default=[], help="Target an endpoint id; repeat as needed")
    deploy.add_argument("--version", default="0.4.0")
    deploy.add_argument("--execute", action="store_true", help="Queue jobs; omission creates a dry-run plan")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.token:
        raise SystemExit("Set UIG_INGEST_TOKEN or pass --token")
    if args.action == "inventory":
        result = _request(args.server, args.token, "/v1/endpoints")
    elif args.action == "discover":
        result = _request(args.server, args.token, "/v1/discovery-sessions", "POST", {"requested_by": "network-cli"})
    elif args.action == "deployments":
        result = _request(args.server, args.token, f"/v1/deployments?limit={max(1, min(args.limit, 250))}")
    else:
        result = _request(args.server, args.token, "/v1/deployments", "POST", {
            "security_group": args.group,
            "endpoint_ids": args.endpoint,
            "version": args.version,
            "execute": args.execute,
            "requested_by": "network-cli",
        })
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
