FROM python:3.12-alpine

RUN pip install --no-cache-dir \
      flask==3.0.3 \
      pyjwt==2.8.0 \
      lxml==5.2.2 \
      jinja2==3.1.4

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8080
CMD ["python", "/app/app.py"]
