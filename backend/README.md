# E2EE Chat Backend

Skeleton FastAPI service for an end-to-end encrypted chat platform.

## Structure

- `app/core` – settings, security primitives.
- `app/cryptography` – key management & Signal-style protocol helpers.
- `app/api/routes` – HTTP + WebSocket endpoints.
- `app/services` – business logic orchestration.
- `app/db` – SQLAlchemy models, sessions, repositories.
- `app/websocket` – realtime connection management.
- `tests` – pytest fixtures and placeholder suites.

## Getting Started

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

