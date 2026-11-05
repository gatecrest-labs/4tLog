"""Capture a scrubbed FortiAnalyzer fixture for the replay tests.

Runs the read-only API self-test against a FortiAnalyzer target from
``faz_targets.json`` while recording every JSON-RPC exchange, then writes
``tests/fixtures/faz_<version>/exchanges.json``.

    uv run python scripts/record_faz_fixture.py
    uv run python scripts/record_faz_fixture.py --label "FortiAnalyzer Primary"
    uv run python scripts/record_faz_fixture.py --literal "Acme Corp=ORG"

Device names and the appliance hostname are replaced automatically; pass
--literal OLD=NEW for anything else (company names, domains). The scrubber
also replaces secrets, IPv4 addresses, serial numbers and e-mail addresses,
but it is best-effort: READ the output before committing it -- this
repository is public. For the data-shaped checks (FortiView row fields) to
mean anything, record against a FortiAnalyzer that is receiving logs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _discover_literals(client) -> dict[str, str]:
    lit: dict[str, str] = {}
    for n, d in enumerate(client.get_devices(), 1):
        # a device named after its model (platform_str) is not identifying
        if d.get("name") and d["name"] != d.get("platform"):
            lit[d["name"]] = f"FGT-LAB-{n}"
    host = (client.get_sys_status() or {}).get("Hostname")
    if host:
        lit[host] = "FAZ-LAB"
    return lit


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--label", help="faz_targets.json label (default: first target)")
    ap.add_argument("--out", help="output directory (default tests/fixtures/faz_<ver>)")
    ap.add_argument("--literal", action="append", default=[], metavar="OLD=NEW")
    args = ap.parse_args(argv)

    from app.config import Config
    from app.faz_client import FAZClient
    from app.faz_recorder import Recorder, Scrubber
    from app.faz_selftest import run_selftest
    from app.faz_targets import get_target, list_targets

    target = get_target(args.label) if args.label else next(iter(list_targets()), None)
    if not target:
        print("No FAZ target found in faz_targets.json.", file=sys.stderr)
        return 2

    with FAZClient(
        host=target["host"],
        token=target.get("token", ""),
        adom=target.get("adom", "root"),
        verify_ssl=Config.FAZ_VERIFY_SSL,
        timeout=Config.FAZ_REQUEST_TIMEOUT,
    ) as client:
        literals = _discover_literals(client)
        for pair in args.literal:
            old, _, new = pair.partition("=")
            if not old or not new:
                ap.error(f"--literal expects OLD=NEW, got {pair!r}")
            literals[old] = new

        version = client.version
        if version is None:
            print("Could not read the FortiAnalyzer version; refusing to record.", file=sys.stderr)
            return 2
        out_dir = (
            Path(args.out)
            if args.out
            else ROOT
            / "tests"
            / "fixtures"
            / f"faz_{version.major}.{version.minor}.{version.patch}"
        )
        out_file = out_dir / "exchanges.json"
        if out_file.exists():
            out_file.unlink()  # one capture == one process == one mapping

        client._recorder = Recorder(out_file, scrubber=Scrubber(literals))
        report = run_selftest(client)
        print(f"self-test: {report['summary']}")

    print(f"wrote {out_file}")
    print("Review it for anything identifying before you commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
