#!/bin/bash
# A TURN relay (coturn) on the instance itself, for callers who cannot reach each other directly.
# Browsers try a direct path first and this relay second; if both fail the client falls back to
# relaying audio over the app's own WebSocket. The relay only forwards DTLS-SRTP it cannot decrypt.
#
# coturn runs in Docker (Amazon Linux 2023 has no coturn package) with host networking, from a
# pinned image. Ports, opened in .ebextensions/03-turn.config:
#   3478 udp+tcp   TURN
#   5349 tcp       TURN over TLS, with the Let's Encrypt certificate from 10-https.sh
#   49152-49252 udp  relayed media
#
# The shared secret is made here once and kept in /etc/marmot (outside the app directory, so
# redeploys keep it). The app reads the relay address and secret from /etc/marmot/turn.json
# (TURN_CONFIG) on every /api/ice request and mints short-lived credentials from it.
# TURN_URLS / TURN_SECRET environment properties, when set, take precedence (an external relay).
#
# Runs on every deploy and config change; coturn is only restarted when its config changed,
# so a deploy does not cut relayed calls. A failure here leaves calls on STUN and the socket
# fallback, and only logs.
set -u
log() { echo "[turn] $*"; }
IMAGE=coturn/coturn:4.18.0
MIN_PORT=49152 MAX_PORT=49252

cfg() { /opt/elasticbeanstalk/bin/get-config environment -k "$1" 2>/dev/null || true; }
if [ "$(cfg MARMOT_TURN)" = off ]; then
  log "MARMOT_TURN=off; stopping any relay"
  docker rm -f coturn >/dev/null 2>&1 || true; rm -f /etc/marmot/turn.json; exit 0
fi

TOK=$(curl -s -m 5 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
md() { curl -s -m 5 -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/$1"; }
PUBLIC=$(md public-ipv4) PRIVATE=$(md local-ipv4)
[ -n "$PUBLIC" ] && [ -n "$PRIVATE" ] || { log "no public/private IP; skipping"; exit 0; }
HOST=$(cfg MARMOT_HOST); [ -n "$HOST" ] || HOST="$(echo "$PUBLIC" | tr . -).sslip.io"
log "host: $HOST ($PUBLIC, private $PRIVATE)"

if ! command -v docker >/dev/null 2>&1; then
  log "installing docker"
  dnf install -y -q docker || { log "docker install failed"; exit 0; }
fi
systemctl enable --now docker >/dev/null 2>&1 || { log "docker would not start"; exit 0; }

# the secret: made once, readable by the app (webapp) and root only
install -d -m 750 -o root -g webapp /etc/marmot
[ -s /etc/marmot/turn-secret ] || (umask 077; openssl rand -hex 32 > /etc/marmot/turn-secret)
SECRET=$(cat /etc/marmot/turn-secret)

# TLS: copies of the certificate the coturn user (nobody, 65534) can read; renewals refresh them
install -d -m 750 -o root -g 65534 /etc/coturn
LIVE=/etc/letsencrypt/live/$HOST TLS=""
cat > /usr/local/bin/marmot-turn-certs <<SH
#!/bin/sh
# copies the Let's Encrypt certificate for coturn; run by certbot after each renewal
[ -f $LIVE/fullchain.pem ] || exit 0
install -m 640 -o root -g 65534 $LIVE/fullchain.pem /etc/coturn/cert.pem
install -m 640 -o root -g 65534 $LIVE/privkey.pem /etc/coturn/key.pem
[ "\${1:-}" = restart ] && docker restart coturn >/dev/null 2>&1
exit 0
SH
chmod 755 /usr/local/bin/marmot-turn-certs
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nexec /usr/local/bin/marmot-turn-certs restart\n' > /etc/letsencrypt/renewal-hooks/deploy/coturn.sh
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/coturn.sh
/usr/local/bin/marmot-turn-certs
if [ -f /etc/coturn/cert.pem ]; then
  TLS="tls-listening-port=5349
cert=/etc/coturn/cert.pem
pkey=/etc/coturn/key.pem
no-tlsv1
no-tlsv1_1"
else log "no certificate for $HOST yet: TURN over TLS is off until the next deploy"; fi

NEW=$(mktemp)
cat > "$NEW" <<CONF
# written by .platform/hooks/postdeploy/20-turn.sh; edits are overwritten on deploy
listening-port=3478
external-ip=$PUBLIC/$PRIVATE
min-port=$MIN_PORT
max-port=$MAX_PORT
realm=$HOST
use-auth-secret
static-auth-secret=$SECRET
fingerprint
no-cli
no-multicast-peers
no-tcp-relay
stale-nonce=600
user-quota=12
total-quota=200
log-file=stdout
simple-log
$TLS
# never relay into the instance, the VPC or the metadata service
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.0.0.0-192.0.0.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=240.0.0.0-255.255.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
# (the public IP stays allowed: when both callers are relayed, each one's peer is this relay)
CONF

CHANGED=1
if [ -f /etc/coturn/turnserver.conf ] && cmp -s "$NEW" /etc/coturn/turnserver.conf; then CHANGED=0; fi
install -m 640 -o root -g 65534 "$NEW" /etc/coturn/turnserver.conf; rm -f "$NEW"

RUNNING=$(docker inspect -f '{{.State.Running}} {{.Config.Image}}' coturn 2>/dev/null || true)
if [ "$CHANGED" = 1 ] || [ "$RUNNING" != "true $IMAGE" ]; then
  log "starting $IMAGE"
  docker pull -q "$IMAGE" >/dev/null || { log "image pull failed"; exit 0; }
  docker rm -f coturn >/dev/null 2>&1 || true
  docker run -d --name coturn --restart unless-stopped --network host \
    --log-opt max-size=10m --log-opt max-file=3 \
    -v /etc/coturn:/etc/coturn:ro "$IMAGE" -c /etc/coturn/turnserver.conf >/dev/null \
    || { log "coturn would not start"; exit 0; }
else log "coturn already running with this config"; fi

URLS="\"turn:$HOST:3478?transport=udp\",\"turn:$HOST:3478?transport=tcp\""
[ -n "$TLS" ] && URLS="$URLS,\"turns:$HOST:5349?transport=tcp\""
TMPJ=$(mktemp)
printf '{"urls":[%s],"secret":"%s"}\n' "$URLS" "$SECRET" > "$TMPJ"
install -m 640 -o root -g webapp "$TMPJ" /etc/marmot/turn.json; rm -f "$TMPJ"
log "relay on: $URLS"
exit 0
