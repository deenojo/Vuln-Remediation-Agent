# Older Debian base on purpose, so the image scan finds OS-level CVEs for Copa to patch in Week 4.
FROM python:3.9-slim-bullseye
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER nobody
EXPOSE 5000
CMD ["python", "app.py"]
