# Platform upgrade: Python 3.9 (end of life Oct 2025) -> 3.12 on current Debian 12.
FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV HOST=0.0.0.0
USER nobody
EXPOSE 5000
CMD ["python", "app.py"]
