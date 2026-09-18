# Placitum json

English · [Русский](README.ru.md)

Placitum API contract inspector: it checks a call against its description, OpenAPI 3.0/3.1 or a
standalone JSON Schema, as the profile chooses. It works in both phases, and the phases are
independent: the operation is found by method and path, which come in every message. WebSocket
messages are checked against schemas as well, in the `frame` section of a profile.

The body must be **complete**. A JSON prefix is never valid, so the inspector does not validate a
truncated body at all and follows the profile policy instead: `on_truncated` is `deny` where
unverifiable data must not pass, `allow` where large bodies are legitimate.

```
module ──► waf.req.json ──►  json  ──► allow | deny | score
                               │
                               ├── body and headers: from the buffer by locator
                               └── profile: specification, outcome policy, dataset writes
```

## Layout

```
cmd/inspector/     bus, waf.req.json, both phases
cmd/probe/         health check: the _probe profile answers deny without the buffer
internal/schema/   OpenAPI and JSON Schema compilation, operation lookup, findings
internal/validate/ check order: is the body complete? does it parse? does it match?
internal/decide/   profile policy → verdict, a pure function
internal/config/   environment, inspector.conf, profiles and hot reload
internal/desired/  generation from KV (policy/json), unpacking to disk
profiles/          default (off) and _probe
deploy/            Dockerfile
```

Presence frame, machine snapshot, flow counters, log levels and the geo coder client come from
[`placitum-shared`](https://github.com/exemt/placitum-shared).

## Build

```sh
docker build -f deploy/Dockerfile -t placitum/json .
```

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## Profiles

A profile is a specification plus a policy: what to do with a mismatch, a truncated body, or an
operation the description does not have. The image ships two profiles. `default` is off, because
there is nothing to check against until the controller delivers a contract, and `_probe` serves the
health check. Real profiles come from the panel as generations and replace the directory as a
whole; `_probe` is added back from the image.

A route whose profile is missing gets a denial, not a fallback to `default`: checking against the
wrong contract is not a milder check, it is a check of the wrong thing.

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
