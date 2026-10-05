#!/bin/bash
# HTTPS straight on the instance: browsers only give WebCrypto and the microphone to secure pages,
# and an https page (GitHub Pages) can't call an http server.
#
# Host name: the MARMOT_HOST environment property if set (a domain pointed at this instance),
# otherwise <elastic-ip-with-dashes>.sslip.io, a free name that resolves to the IP inside it.
# The certificate comes from Let's Encrypt over HTTP-01 (nginx serves the challenge, see
# .platform/nginx/conf.d/elasticbeanstalk/acme.conf) and is renewed by a systemd timer.
# Port 80 keeps working unchanged, so copies of the client that use http:// still connect.
#
# EB rebuilds /etc/nginx from .platform on every deploy, so this runs on every deploy (and
# config change, via confighooks) and puts the https server block back. A failure here leaves
# the http site up and only logs.
set -u
log() { echo "[https] $*"; }

HOST=$(/opt/elasticbeanstalk/bin/get-config environment -k MARMOT_HOST 2>/dev/null || true)
if [ -z "$HOST" ]; then
  TOK=$(curl -s -m 5 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  IP=$(curl -s -m 5 -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/meta-data/public-ipv4)
  [ -n "$IP" ] || { log "no public IP; skipping"; exit 0; }
  HOST="$(echo "$IP" | tr . -).sslip.io"
fi
log "host: $HOST"

CERTBOT=/opt/certbot/bin/certbot
if [ ! -x "$CERTBOT" ]; then
  log "installing certbot"
  python3 -m venv /opt/certbot && /opt/certbot/bin/pip install -q --upgrade pip && /opt/certbot/bin/pip install -q certbot \
    || { log "certbot install failed"; exit 0; }
fi

mkdir -p /var/www/letsencrypt
LIVE=/etc/letsencrypt/live/$HOST
if [ ! -f "$LIVE/fullchain.pem" ]; then
  log "requesting a certificate"
  "$CERTBOT" certonly --webroot -w /var/www/letsencrypt -d "$HOST" --non-interactive --agree-tos \
    --register-unsafely-without-email --keep-until-expiring || { log "certificate request failed"; exit 0; }
fi

cat > /etc/nginx/conf.d/marmot-https.conf <<CONF
map \$http_upgrade \$marmot_connection { default upgrade; '' close; }
server {
    listen 443 ssl http2;
    server_name $HOST;
    ssl_certificate     $LIVE/fullchain.pem;
    ssl_certificate_key $LIVE/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:marmot_ssl:5m;
    add_header Strict-Transport-Security "max-age=31536000" always;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$marmot_connection;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
}
CONF

if nginx -t 2>/dev/null; then systemctl reload nginx && log "https on for $HOST"
else log "nginx rejected the https config; removing it"; rm -f /etc/nginx/conf.d/marmot-https.conf; nginx -t && systemctl reload nginx; fi

# twice-daily renewal; certbot only renews when the certificate is close to expiring
cat > /etc/systemd/system/certbot-renew.service <<UNIT
[Unit]
Description=Renew the Let's Encrypt certificate
[Service]
Type=oneshot
ExecStart=$CERTBOT renew --quiet --webroot -w /var/www/letsencrypt --deploy-hook "systemctl reload nginx"
UNIT
cat > /etc/systemd/system/certbot-renew.timer <<UNIT
[Unit]
Description=Renew the Let's Encrypt certificate twice a day
[Timer]
OnCalendar=*-*-* 03,15:17:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload && systemctl enable --now certbot-renew.timer >/dev/null 2>&1
exit 0
