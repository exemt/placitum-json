# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus. It needs no
address and no service, and adding a copy touches neither the protection node nor the
configuration. Usually `placitum-core` installs it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.json` queue, audit, log, profile generations |
| Buffer Redis | for body checks | body and headers come as a locator and are read from here |
| Controller | yes | sends profiles as generations |
| `keeper` | if a profile writes outcomes to datasets | the write is a request to `waf.sets.<set>.event` |
| `geo` | if a dataset write uses a subnet or a system | announcements and AS number by address |

The inspector does not need the internal Redis.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `REDIS_URL` | from `inspector.conf` | buffer. Empty starts with a warning and treats **every body** as unavailable; named but not answering stops the start |
| `WAF_JSON_SUBJECT` | `waf.req.json` | subscription |
| `WAF_JSON_NAME` | `json` | name in the inspector registry and the presence frame |
| `WAF_JSON_QUEUE` | the name | queue group on the bus |
| `WAF_JSON_PROFILES` | `./profiles`; `/app/profiles` in the image | profiles |
| `WAF_JSON_DATA` | `<profiles>.applied`; `/var/lib/waf/json` in the image | where rollout puts the applied generation |
| `WAF_JSON_RELOAD_EVERY` | `1s` | how often to check the profile directory |
| `WAF_JSON_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_JSON_WORKERS` | number of CPUs | check workers |
| `WAF_JSON_QUEUE_DEPTH`, `WAF_JSON_QUEUE_FULL`, `WAF_JSON_QUEUE_EXPAND` | `256`, `drop`, `off` | queue and overflow behaviour; the same through `inspector.conf` |
| `WAF_JSON_RESERVE_MS`, `WAF_JSON_MIN_BUDGET_MS` | `2`, `2` | reserve before the wave deadline and the minimum budget below which a check does not start |
| `WAF_JSON_VERSIONS` | `2` | accepted message schema versions |
| `WAF_JSON_GEO_ADDR` | empty | geo coder (`host:port`); empty makes subnet and system writes answer with a rejection |
| `WAF_JSON_GEO_TIMEOUT`, `WAF_JSON_GEO_NEG_MAX` | `500ms`, `0` | coder wait within the message budget and negative cache limit |
| `WAF_JSON_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |

## Docker Compose

```yaml
services:
  inspector-json:
    image: placitum/json
    scale: 2
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      WAF_JSON_SUBJECT: waf.req.json
      WAF_JSON_NAME: json
      WAF_JSON_GEO_ADDR: geo:50051
      WAF_JSON_LOG: info
    depends_on: [nats, redis]
```

## Checking

The image declares a `HEALTHCHECK`: the probe sends an ordinary bus message with the `_probe`
profile and expects `deny` for a path outside its bindings. A healthy container means the bus
connection, the subscription, the compiled contracts and the worker pool are alive; a TCP ping to
NATS would say nothing about any of them.

```sh
docker exec <container> json-probe --quiet --timeout 1s --uri /healthcheck
```

A healthy start logs the bus and buffer connections, the loaded profiles and the worker count,
then a presence frame every four seconds.

## Pitfalls

- **An empty `REDIS_URL` does not stop the start**, but makes body checks pointless: every body is
  "unavailable", and the profile policy decides. The start log shows a warning.
- **A missing profile means a denial, not a fallback to `default`.** Checking against the wrong
  contract is not a milder check.
- **A generation replaces the directory as a whole.** The `_probe` profile is not lost: it is added
  back from the image, otherwise the health check would turn red after the first rollout.
