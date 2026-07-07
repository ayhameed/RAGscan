FROM python:3.12-slim

WORKDIR /app/backend

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2-dev libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
COPY scripts/ /app/scripts/
COPY sample_data/ /app/sample_data/
COPY many_vuln_rhsa.xml /app/many_vuln_rhsa.xml
COPY nessus_v_unknown.nessus /app/nessus_v_unknown.nessus

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]