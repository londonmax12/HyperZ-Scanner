FROM python:3.12-alpine

RUN pip install --no-cache-dir \
      flask==3.0.3 \
      graphene==3.4.3

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 8090
CMD ["python", "/app/server.py"]
