FROM python:3.11-slim

WORKDIR /app

# System deps for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the embedding model so container startup is instant
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" || true

COPY . .

# Default wordlist
RUN [ -f data.txt ] || echo "" > data.txt

EXPOSE 5000

ENV WAF_CONFIG=config.yaml

CMD ["python", "app.py"]
