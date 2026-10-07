# Backend + scanner. Build from the repository root (the scanner lives next to the backend):
#   docker build -f backend/Dockerfile -t securesphere-backend .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY scanner scanner
COPY backend backend

# Never run as root inside the container.
RUN useradd --create-home --uid 10001 appuser
USER appuser

WORKDIR /app/backend
EXPOSE 8000
# --proxy-headers: behind a hosting proxy, use the visitor's real IP (needed for login lockouts).
# Set FORWARDED_ALLOW_IPS to the proxy's address (or "*" on platforms such as Render).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
