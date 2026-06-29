#!/usr/bin/env python3
"""Run the A2A privacy audit service + dashboard.

    python examples/a2a_serve.py                 # → http://localhost:8099
    HOST=0.0.0.0 PORT=8099 python examples/a2a_serve.py   # bind all interfaces

Open the URL for the dashboard; POST desensitized reports to
/api/v1/a2a/report. For a forced-embed deployment, pass trusted_builds to
create_app (see a2a/service.py).
"""

from __future__ import annotations

import os

from federated_agent_audit.a2a.service import create_app

app = create_app()  # uvicorn examples.a2a_serve:app

if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8099"))
    print(f"A2A privacy dashboard → http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
