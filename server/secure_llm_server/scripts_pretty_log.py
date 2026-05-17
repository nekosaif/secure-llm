"""Stream JSON log lines from stdin and pretty-print them with Rich."""

from __future__ import annotations

import json
import sys

try:
    from rich.console import Console
except ImportError:  # pragma: no cover
    Console = None  # type: ignore[assignment]


def main() -> int:
    console = Console() if Console is not None else None
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            if console is not None:
                console.print(line)
            else:
                print(line)
            continue
        ts = obj.get("timestamp", "")
        lvl = str(obj.get("level", "info")).upper().ljust(5)
        comp = obj.get("logger", "")
        ev = obj.get("event", "")
        extra = {k: v for k, v in obj.items() if k not in {"timestamp", "level", "logger", "event"}}
        msg = f"{ts:>17}  {lvl}  {comp}  {ev}  {extra}"
        if console is not None:
            colors = {
                "INFO": "cyan",
                "WARNI": "yellow",
                "WARNING": "yellow",
                "ERROR": "red",
                "DEBUG": "dim",
            }
            console.print(msg, style=colors.get(lvl.strip(), "white"))
        else:
            print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
