"""Run the optional netagent web UI on the local machine."""
from __future__ import annotations

import os
import sys


def main() -> int:
    try:
        import uvicorn
    except ImportError:
        print("Web dependencies are missing. Install with: python -m pip install -e .[web]", file=sys.stderr)
        return 2

    host = os.environ.get("NETAGENT_WEB_HOST", "127.0.0.1").strip()
    port_text = os.environ.get("NETAGENT_WEB_PORT", "8765").strip()
    try:
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("NETAGENT_WEB_PORT must be an integer from 1 to 65535", file=sys.stderr)
        return 2

    token = os.environ.get("NETAGENT_WEB_TOKEN", "")
    if host not in {"127.0.0.1", "localhost", "::1"} and len(token) < 24:
        print("Refusing LAN exposure: set NETAGENT_WEB_TOKEN to a random value of at least 24 characters.", file=sys.stderr)
        return 2

    print(f"netagent web UI: http://{host}:{port}")
    print("Live config apply/rollback are not exposed by this web API.")
    uvicorn.run("netagent.webapp:APP", host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
