FROM python:3.12-slim

LABEL maintainer="Kosha Gohil <gohilkosha@gmail.com>"
LABEL project="Zero-Standing-Privilege-Honeytoken-Mesh"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["simulate"]
