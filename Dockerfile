FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root unprivileged worker (Least Privilege - Chapter 4.2 & 5.1)
RUN useradd -m -u 1000 -s /bin/bash mlops_worker

# Copy dependency definition
COPY requirements.txt .

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files (keys/private_key.pem is strictly excluded via .dockerignore)
COPY . .

# Ensure directories exist with appropriate least-privilege permissions and ownership
RUN mkdir -p /app/keys /app/artifacts /app/reports /app/data_storage /app/feature_store_storage && \
    chmod 755 /app/keys /app/artifacts /app/reports /app/data_storage /app/feature_store_storage && \
    chown -R mlops_worker:mlops_worker /app

USER mlops_worker

# Set python path
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

CMD ["python", "experiments/run_all_experiments.py"]
