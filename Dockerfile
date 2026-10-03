FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
COPY alembic.ini .
COPY backend ./backend
COPY sdk ./sdk
COPY data ./data

RUN pip install --no-cache-dir . ./sdk/python

EXPOSE 8000
CMD ["sh", "-c", "python -m alembic upgrade head && uvicorn backend.apps.gateway.main:app --host 0.0.0.0 --port 8000"]
