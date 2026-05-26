FROM nginx:1.27-alpine

# Build-time generated TLS: a local CA signs a server cert with
# SAN=localhost,127.0.0.1 so the container's 443 (mapped to a random
# localhost port by testcontainers) verifies cleanly when the harness
# trusts the CA via SSL_CERT_FILE. CA cert is also copied to a known
# path so the harness can extract it via CopyFileFromContainer.
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/tls /export \
 && openssl genrsa -out /etc/nginx/tls/ca.key 2048 \
 && openssl req -x509 -new -nodes -key /etc/nginx/tls/ca.key \
      -sha256 -days 365 \
      -subj "/CN=vuln-static-ca" \
      -out /etc/nginx/tls/ca.crt \
 && openssl genrsa -out /etc/nginx/tls/server.key 2048 \
 && openssl req -new -key /etc/nginx/tls/server.key \
      -subj "/CN=localhost" \
      -out /tmp/server.csr \
 && printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > /tmp/san.cnf \
 && openssl x509 -req -in /tmp/server.csr \
      -CA /etc/nginx/tls/ca.crt -CAkey /etc/nginx/tls/ca.key -CAcreateserial \
      -out /etc/nginx/tls/server.crt -days 365 \
      -extfile /tmp/san.cnf \
 && cp /etc/nginx/tls/ca.crt /export/ca.crt

COPY nginx.conf /etc/nginx/nginx.conf
COPY html/      /usr/share/nginx/html/

EXPOSE 80 443
