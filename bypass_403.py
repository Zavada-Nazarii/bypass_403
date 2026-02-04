#!/usr/bin/env python3
"""
Python reimplementation of the original bypass-403.sh helper.

The script loads path, header and miscellaneous bypass techniques from
JSON files so that the payloads can be tweaked without touching the code.
It accepts a single URL or a file with many URLs and runs every technique
against each target while reporting the HTTP status and body length.
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
PATH_FILE = SCRIPT_DIR / "path_techniques.json"
HEADER_FILE = SCRIPT_DIR / "header_techniques.json"
MISC_FILE = SCRIPT_DIR / "misc_techniques.json"

DEFAULT_HEADERS = {
  "User-Agent": "bypass-403-python",
  "Accept": "*/*",
  "Accept-Language": "en-US,en;q=0.5",
}

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


@dataclass
class Target:
  raw_input: str
  origin: str
  path: str

  @property
  def default_url(self) -> str:
    """Origin plus the user provided path."""
    if self.path:
      return f"{self.origin}/{self.path}"
    return f"{self.origin}/"

  def template_vars(self) -> Dict[str, str]:
    path_with_slash = f"/{self.path}" if self.path else "/"
    return {"origin": self.origin, "path": self.path, "path_with_slash": path_with_slash}


def load_json(path: Path) -> List[Dict[str, object]]:
  with path.open(encoding="utf-8") as handle:
    return json.load(handle)


def parse_url(value: str) -> Target:
  parsed = urllib.parse.urlsplit(value)
  if not parsed.scheme or not parsed.netloc:
    raise ValueError(f"URL '{value}' must include scheme and host")
  origin = f"{parsed.scheme}://{parsed.netloc}"
  clean_path = parsed.path.lstrip("/")
  if parsed.query:
    suffix = f"?{parsed.query}"
    clean_path = f"{clean_path}{suffix}" if clean_path else suffix
  return Target(raw_input=value, origin=origin, path=clean_path)


def parse_base_and_path(base: str, path: str) -> Target:
  base = base.rstrip("/")
  if "://" not in base:
    raise ValueError(f"Base '{base}' must include scheme, e.g. https://target")
  return parse_url(f"{base}/{path.lstrip('/')}")


def read_targets(args: argparse.Namespace) -> List[Target]:
  targets: List[Target] = []
  if args.url:
    for url in args.url:
      targets.append(parse_url(url))
  if args.base or args.path:
    if not (args.base and args.path):
      raise ValueError("--base and --path must be used together")
    targets.append(parse_base_and_path(args.base, args.path))
  if args.targets_file:
    file_path = Path(args.targets_file)
    if not file_path.is_file():
      raise ValueError(f"Targets file '{args.targets_file}' not found")
    with file_path.open(encoding="utf-8") as handle:
      for line in handle:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
          continue
        if "://" in stripped:
          targets.append(parse_url(stripped))
          continue
        parts = stripped.split(maxsplit=1)
        if len(parts) == 2:
          targets.append(parse_base_and_path(parts[0], parts[1]))
        else:
          raise ValueError(f"Cannot parse target line '{stripped}'")
  if not targets:
    raise ValueError("Provide at least one --url, --base/--path pair, or --targets-file")
  return targets


def build_ssl_context(verify: bool) -> ssl.SSLContext:
  if verify:
    return ssl.create_default_context()
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  return context


def send_request(
  url: str,
  *,
  method: str = "GET",
  headers: Optional[Dict[str, str]] = None,
  body: Optional[str] = None,
  timeout: float,
  context: ssl.SSLContext,
) -> Tuple[int, int, Optional[str]]:
  req_headers = dict(DEFAULT_HEADERS)
  if headers:
    req_headers.update(headers)
  data: Optional[bytes]
  if body is None:
    data = None
  elif isinstance(body, bytes):
    data = body
  else:
    data = body.encode("utf-8")
  request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
  try:
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
      response_body = response.read()
      return response.status, len(response_body), None
  except urllib.error.HTTPError as exc:
    error_body = exc.read()
    return exc.code, len(error_body), exc.reason


def run_techniques(
  targets: Sequence[Target],
  path_items: Sequence[Dict[str, object]],
  header_items: Sequence[Dict[str, object]],
  misc_items: Sequence[Dict[str, object]],
  *,
  timeout: float,
  verify_tls: bool,
  spoof_ip: str,
) -> None:
  context = build_ssl_context(verify_tls)
  for target in targets:
    fmt_vars = target.template_vars()
    fmt_vars["spoof_ip"] = spoof_ip
    print(f"\n==> Target: {target.default_url}")
    for category, items in (
      ("path", path_items),
      ("header", header_items),
      ("misc", misc_items),
    ):
      for item in items:
        name = item.get("name", "unnamed")
        template = item.get("path_template")
        url_template = template if isinstance(template, str) else target.default_url
        try:
          url = url_template.format(**fmt_vars)
        except KeyError as err:
          print(f"  [{category}/{name}] template error: {err}")
          continue
        method = item.get("method", "GET")
        headers = item.get("headers")
        body = item.get("body")
        if headers and isinstance(headers, dict):
          formatted_headers = {}
          for header_name, header_value in headers.items():
            formatted_headers[header_name] = header_value.format(**fmt_vars)
        else:
          formatted_headers = None
        try:
          status, size, reason = send_request(
            url,
            method=method,
            headers=formatted_headers,
            body=body,
            timeout=timeout,
            context=context,
          )
          success = 200 <= status < 400
          header_info = formatted_headers if category == "header" else None
          print(format_result(category, name, url, status, size, success, reason, header_info))
        except urllib.error.URLError as err:
          header_info = formatted_headers if category == "header" else None
          print(format_result(category, name, url, None, 0, False, err.reason, header_info))
    fetch_wayback_snapshot(target.default_url, timeout=timeout)


def format_result(
  category: str,
  name: str,
  url: str,
  status: Optional[int],
  size: int,
  success: bool,
  reason: Optional[str],
  headers: Optional[Dict[str, str]],
) -> str:
  label = f"{GREEN}PASS{RESET}" if success else f"{RED}FAIL{RESET}"
  status_text = str(status) if status is not None else "-"
  reason_display = f" ({reason})" if reason else ""
  header_display = ""
  if headers:
    header_pairs = ", ".join(f"{key}: {value}" for key, value in headers.items())
    header_display = f" | headers: {header_pairs}"
  return f"  [{category}/{name}] {label} {status_text} {size}B -> {url}{reason_display}{header_display}"


def fetch_wayback_snapshot(url: str, *, timeout: float) -> None:
  endpoint = "https://archive.org/wayback/available"
  query = urllib.parse.urlencode({"url": url})
  request_url = f"{endpoint}?{query}"
  try:
    with urllib.request.urlopen(request_url, timeout=timeout) as response:
      payload = json.loads(response.read().decode("utf-8"))
  except Exception as err:
    print(f"  [wayback] lookup failed: {err}")
    return
  snapshot = payload.get("archived_snapshots", {}).get("closest")
  if not snapshot:
    print("  [wayback] no snapshots available")
    return
  available = snapshot.get("available")
  snap_url = snapshot.get("url")
  print(f"  [wayback] available={available} url={snap_url}")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Run 403 bypass payloads against targets.")
  parser.add_argument("--url", action="append", help="Full URL to test (can be used multiple times)")
  parser.add_argument("--base", help="Base URL such as https://example.com")
  parser.add_argument("--path", help="Path portion without leading slash, used with --base")
  parser.add_argument("--targets-file", help="File with URLs or base+path pairs")
  parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
  parser.add_argument(
    "--verify-tls",
    action="store_true",
    help="Verify TLS certificates (default: disabled to mimic curl -k)",
  )
  parser.add_argument(
    "--spoof-ip",
    default="192.168.3.135",
    help="Value для IP-заголовків (default: 192.168.3.135)",
  )
  return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
  args = parse_args(argv)
  try:
    targets = read_targets(args)
  except ValueError as err:
    print(f"error: {err}", file=sys.stderr)
    return 1
  path_items = load_json(PATH_FILE)
  header_items = load_json(HEADER_FILE)
  misc_items = load_json(MISC_FILE)
  run_techniques(
    targets,
    path_items,
    header_items,
    misc_items,
    timeout=args.timeout,
    verify_tls=args.verify_tls,
    spoof_ip=args.spoof_ip,
  )
  return 0


if __name__ == "__main__":
  sys.exit(main())
