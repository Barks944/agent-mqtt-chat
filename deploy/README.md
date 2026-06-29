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

---

# Running the agentmsg daemon on boot

These files keep an agent's daemon (`agentmsg daemon run`) alive across reboots.
`daemon run` runs in the **foreground**, which is exactly what a service manager
expects to supervise.

## Per-agent isolation is REQUIRED

Every agentmsg agent — its identity, trust store, message DB, IPC endpoint, lock
file, and daemon — is derived from a single data directory (`AGENTMSG_HOME`). To
run **multiple agents on one host you MUST give each its own `AGENTMSG_HOME`** and
its own service instance. Two agents sharing a home collide on identity, store,
and the single-daemon lock. With `AGENTMSG_HOME` unset, agentmsg falls back to the
per-user platform data directory (one agent per OS user).

## Files

- `systemd/agentmsg.service` — Linux systemd unit. Runs `agentmsg daemon run`
  under a fixed `AGENTMSG_HOME`. Edit the `User`, `Environment=AGENTMSG_HOME`,
  and `ExecStart` placeholders.
- `windows/agentmsg.winsw.xml` — Windows service definition for
  [WinSW](https://github.com/winsw/winsw). Sets `AGENTMSG_HOME` per service.
- `windows/install-service.ps1` — installs the Windows service (WinSW preferred;
  nssm / `sc.exe` / `schtasks` alternatives documented inline).

## Linux (systemd)

```sh
sudo install -m 0644 systemd/agentmsg.service /etc/systemd/system/agentmsg.service
sudoedit /etc/systemd/system/agentmsg.service     # set User, AGENTMSG_HOME, ExecStart
sudo systemctl daemon-reload
sudo systemctl enable --now agentmsg
journalctl -u agentmsg -f                          # follow logs
```

For several agents on one host, copy the unit per agent (e.g.
`agentmsg-alice.service`, `agentmsg-bob.service`) each with a distinct
`AGENTMSG_HOME`, and `enable --now` each.

## Windows

Run an elevated PowerShell prompt:

```powershell
# WinSW (preferred — supports per-service AGENTMSG_HOME):
.\windows\install-service.ps1 `
    -ExePath 'C:\Program Files\agentmsg\agentmsg.exe' `
    -AgentHome 'C:\ProgramData\agentmsg' `
    -WinswPath '.\WinSW.exe'

# Or fall back to sc.exe (one machine-level AGENTMSG_HOME only):
.\windows\install-service.ps1 -AgentHome 'C:\ProgramData\agentmsg'
```

The script also documents `nssm` (best for multiple agents) and a `schtasks`
run-at-startup variant. The daemon writes tracing to `%AGENTMSG_HOME%\daemon.log`
(`$AGENTMSG_HOME/daemon.log` on Linux).
