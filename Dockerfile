FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY app /app/app

RUN pip install --no-cache-dir .

EXPOSE 8211

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8211"]
