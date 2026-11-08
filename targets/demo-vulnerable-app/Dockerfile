# Older (2023) Debian 12 base on purpose, so the image scan finds OS-level CVEs for Copa to patch.
# Debian 11 is past end of life, so its package mirrors no longer serve fixes Copa could apply.
FROM python:3.9.18-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV HOST=0.0.0.0
USER nobody
EXPOSE 5000
CMD ["python", "app.py"]
