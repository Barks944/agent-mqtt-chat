# agentmsg broker deployment

The agentmsg broker is a **public Mosquitto instance acting as a dumb pipe +
access gate**. It authenticates connections with a single shared
username/password over TLS and relays messages without per-topic authorisation.
All real authority comes from the per-message post-quantum signatures that
agentmsg clients verify themselves — the broker is not a trust anchor.

> Broker provisioning is a **manual admin step**. It is intentionally not
> automated: an operator sets up TLS certs and the one shared credential by
> hand, as described below.

## Files

- `mosquitto.conf.example` — minimal broker config (TLS on 8883, anonymous
  disabled, single password file, no ACLs). Copy/adapt to
  `/etc/mosquitto/mosquitto.conf`.

## TLS certificate

The example config expects certs under `/etc/mosquitto/certs/`. Obtain a
Let's Encrypt certificate for the broker hostname
(`your-broker.example.com`), e.g. with certbot, then make the live cert
files available to Mosquitto as `server.crt` / `server.key` (and the CA chain
as `ca.crt`).

## Create the one shared username/password

There is exactly one shared credential for the whole deployment:

```sh
# Creates /etc/mosquitto/passwd and adds the shared username (prompts for the
# password). The -c flag creates/overwrites the file, so only use it once.
mosquitto_passwd -c /etc/mosquitto/passwd <shared-username>
```

Distribute that username/password to the agentmsg clients out of band.

## Run Mosquitto (Docker)

Mount the config, password file, and Let's Encrypt certs, and publish 8883:

```sh
docker run -d --name agentmsg-broker \
  -p 8883:8883 \
  -v "$PWD/mosquitto.conf.example:/etc/mosquitto/mosquitto.conf:ro" \
  -v /etc/mosquitto/passwd:/etc/mosquitto/passwd:ro \
  -v /etc/letsencrypt/live/your-broker.example.com:/etc/mosquitto/certs:ro \
  eclipse-mosquitto
```

> The Let's Encrypt `live/` directory provides `fullchain.pem` and
> `privkey.pem`. Either point the `cafile`/`certfile`/`keyfile` paths in the
> config at those filenames, or expose them to the container as
> `ca.crt` / `server.crt` / `server.key` to match `mosquitto.conf.example`.

## Reloading after credential changes

After editing the password file, reload without dropping connections:

```sh
kill -HUP "$(pidof mosquitto)"   # or: docker kill -s HUP agentmsg-broker
```
