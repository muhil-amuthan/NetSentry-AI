"""
NetSentry-AI — Telecom Network Incident Triage Assistant.

Application entry point.

Run with:

    python app.py

The server listens on http://localhost:8000 by default.
"""

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from src import api
from src.config import APP_DESCRIPTION, APP_NAME, FRONTEND_DIR, HOST, PORT, VERSION

# Create the FastAPI application instance.
app = FastAPI(
    title=APP_NAME,
    description=APP_DESCRIPTION,
    version=VERSION,
)

# Register the API routes (defined in src/api.py).
app.include_router(api.router)

# Serve the static frontend. This mount is registered last so that the API
# routes added above take priority over static file handling.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    # Run the development server. Uvicorn will import the `app` object from
    # this module and serve it on the configured host/port (default 8000).
    uvicorn.run("app:app", host=HOST, port=PORT)
