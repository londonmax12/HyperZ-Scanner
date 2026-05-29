FROM python:3.12-alpine

RUN pip install --no-cache-dir flask==3.0.3

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 8093
CMD ["python", "/app/server.py"]
