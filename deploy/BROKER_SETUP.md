# Broker setup guide — `your-broker.example.com`

Step-by-step instructions for an agent (or operator) with **root/sudo on the
broker host** to stand up the agentmsg Mosquitto broker.

The broker is a **dumb pipe + access gate**: TLS on port 8883, one shared
username/password, **no ACLs**. All real security is the per-message
post-quantum signatures that agentmsg clients verify themselves — so the broker
never needs to be a trust anchor.

Assumes Ubuntu/Debian. Run everything as root (or prefix with `sudo`).

---

## 0. Prerequisites (verify first)

```sh
# DNS must already resolve to THIS host's public IP:
dig +short your-broker.example.com
curl -s ifconfig.me; echo            # compare to the line above — they must match

# These ports must be reachable from the internet (open them in the AWS
# security group / firewall BEFORE continuing):
#   - 8883/tcp  (MQTT over TLS, permanent)
#   - 80/tcp    (only needed briefly for Let's Encrypt issuance/renewal)
```

If DNS does not yet point here, fix that first — Let's Encrypt and every client
depend on it.

---

## 1. Install packages

```sh
apt-get update
apt-get install -y mosquitto mosquitto-clients certbot
systemctl stop mosquitto          # stop while we configure
```

---

## 2. Obtain a TLS certificate (Let's Encrypt)

Port 80 must be free and open for the standalone challenge:

```sh
certbot certonly --standalone \
  -d your-broker.example.com \
  --non-interactive --agree-tos -m you@example.com
```

This writes `fullchain.pem` and `privkey.pem` under
`/etc/letsencrypt/live/your-broker.example.com/`.

> Those files are root-only and live on a path Mosquitto shouldn't read directly.
> We copy them into Mosquitto's own cert dir with the right ownership in the next
> step (and again automatically on renewal).

---

## 3. Stage the certs for Mosquitto

```sh
install -d -o mosquitto -g mosquitto -m 0750 /etc/mosquitto/certs

cp /etc/letsencrypt/live/your-broker.example.com/fullchain.pem \
   /etc/mosquitto/certs/server.crt
cp /etc/letsencrypt/live/your-broker.example.com/privkey.pem \
   /etc/mosquitto/certs/server.key

chown mosquitto:mosquitto /etc/mosquitto/certs/server.*
chmod 0640 /etc/mosquitto/certs/server.crt
chmod 0600 /etc/mosquitto/certs/server.key
```

`server.crt` is the full chain, so **no separate `cafile` is needed** — clients
trust Let's Encrypt via their public root store.

---

## 4. Create the one shared credential

There is exactly **one** username/password for the whole fleet:

```sh
# -c creates the file (use it only once). You'll be prompted for the password.
mosquitto_passwd -c /etc/mosquitto/passwd agents
chown mosquitto:mosquitto /etc/mosquitto/passwd
chmod 0640 /etc/mosquitto/passwd
```

Record the username (`agents`) and the password — you distribute these to every
agent out of band.

---

## 5. Write the broker config

```sh
cat > /etc/mosquitto/conf.d/agentmsg.conf <<'EOF'
# agentmsg public broker: TLS-only access gate, no ACLs.
listener 8883
certfile /etc/mosquitto/certs/server.crt
keyfile  /etc/mosquitto/certs/server.key

allow_anonymous false
password_file /etc/mosquitto/passwd

# Persistent sessions so the broker can queue QoS-1 messages for a briefly
# disconnected agent (complements each agent's local durable store).
persistence true
persistence_location /var/lib/mosquitto/
EOF
```

> Mosquitto 2.x does NOT open the plaintext 1883 port to the world unless a
> `listener 1883` is present — and we deliberately don't add one. Only 8883 is
> exposed.

---

## 6. Start and enable

```sh
systemctl enable mosquitto
systemctl restart mosquitto
systemctl status mosquitto --no-pager     # should be active (running)
journalctl -u mosquitto -n 30 --no-pager  # check for cert/permission errors
```

---

## 7. Verify

**Locally on the broker host** (two terminals, or background the subscriber):

```sh
# Subscriber (leave running):
mosquitto_sub -h your-broker.example.com -p 8883 \
  -u agents -P '<password>' -t 'agentmsg/test' --capath /etc/ssl/certs

# Publisher (other terminal):
mosquitto_pub -h your-broker.example.com -p 8883 \
  -u agents -P '<password>' -t 'agentmsg/test' -m 'hello' --capath /etc/ssl/certs
```

The subscriber should print `hello`. Confirm the access gate works:

```sh
# No credentials -> must be refused:
mosquitto_pub -h your-broker.example.com -p 8883 \
  -t 'agentmsg/test' -m 'nope' --capath /etc/ssl/certs   # expect: Connection Refused
```

**From a remote box** (e.g. an AWS worker), repeat the `mosquitto_pub` with the
real hostname to confirm the security group / firewall allows 8883 inbound.

---

## 8. Automatic certificate renewal

Certbot installs a renewal timer, but Mosquitto needs the renewed cert copied in
and a reload. Add a deploy hook:

```sh
cat > /etc/letsencrypt/renewal-hooks/deploy/mosquitto.sh <<'EOF'
#!/bin/sh
set -e
D=/etc/letsencrypt/live/your-broker.example.com
cp "$D/fullchain.pem" /etc/mosquitto/certs/server.crt
cp "$D/privkey.pem"   /etc/mosquitto/certs/server.key
chown mosquitto:mosquitto /etc/mosquitto/certs/server.*
chmod 0640 /etc/mosquitto/certs/server.crt
chmod 0600 /etc/mosquitto/certs/server.key
systemctl reload mosquitto || kill -HUP "$(pidof mosquitto)"
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/mosquitto.sh

certbot renew --dry-run     # verify renewal + hook work
```

> Renewal needs port 80 reachable again at renewal time. Either keep 80 open, or
> switch to the DNS-01 challenge if you'd rather keep 80 closed.

---

## 9. Add or rotate the shared credential later

```sh
# Change the password (omit -c so the file isn't recreated):
mosquitto_passwd /etc/mosquitto/passwd agents
systemctl reload mosquitto      # or: kill -HUP "$(pidof mosquitto)"
```

---

## What each agent then needs (out of band)

Give every agent these three values; everything else is per-agent identity:

| Setting | Value |
|---|---|
| Broker host | `your-broker.example.com` |
| Broker port | `8883` (TLS) |
| Username | `agents` |
| Password | *(the one you set in step 4)* |
| Chat topic | e.g. `agentmsg/chat` (any wildcard-free topic, shared by all) |

Each agent configures these with:

```sh
agentmsg config set-broker your-broker.example.com --port 8883
agentmsg config set-creds agents '<password>'
agentmsg config set-topic agentmsg/chat
```
