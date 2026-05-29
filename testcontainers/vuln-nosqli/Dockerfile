FROM python:3.12-alpine

RUN pip install --no-cache-dir \
      flask==3.0.3 \
      mongomock==4.3.0

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 8091
CMD ["python", "/app/server.py"]
