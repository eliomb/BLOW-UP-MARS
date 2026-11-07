FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data HOME=/data
# ssh client only (ssh, ssh-keygen, ssh-keyscan); drop pip; unprivileged user owning only /data
# Alpine splits the NSE runtime and scripts into separate packages.
# Nmap -sV invokes NSE, so nmap alone cannot complete service detection.
RUN apk add --no-cache openssh-client-default nmap nmap-nselibs nmap-scripts \
 && test -f /usr/share/nmap/nse_main.lua \
 && test -f /usr/share/nmap/scripts/script.db \
 && nmap --script-help banner >/dev/null \
 && (python -m pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true) \
 && addgroup -S -g 10001 app && adduser -S -u 10001 -G app -H -h /data -s /sbin/nologin app \
 && mkdir -p /data/keys && chown -R 10001:10001 /data && chmod 700 /data /data/keys
WORKDIR /srv
COPY app/ /srv/
RUN chmod -R a-w,a+rX /srv
VOLUME /data
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8080/healthz',timeout=2)"
CMD ["python", "server.py"]
