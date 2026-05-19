# DShield Vector-Based Long-Tail Log Analysis

Vectorize the noise. Surface the novel.

DShield honeypot sensors capture a lot of attacker activity, most of which is
commodity scanning. The interesting things — first-seen techniques, niche
reconnaissance, evolving campaigns — sit in the long tail. This project adds
an offline layer that:

1. **Reads** Cowrie logs from a SecurityOnion-managed Elasticsearch (read-only).
2. **Deduplicates** repeated payloads by hashing the normalised event text.
3. **Enriches** each unique payload with a local LLM (description, MITRE ATT&CK IDs, IOCs, intent, confidence) and an embedding model (768-dim vector).
4. **Clusters** at three layers (commands → sessions → IPs), names session clusters as **playbooks**, mines multi-session **campaigns**, and grounds source IPs against free-tier threat-intel feeds.
5. **Writes** to separate, project-owned, ECS-compliant indices.

## Install

```bash
sudo bash setup/setup.sh
```

Idempotent. Requires `.env` + `config/local.yaml` filled in, and a reachable
LLM server. See [docs/reference.md](docs/reference.md) for setup details,
configuration, and operational workflows.

## Run

```bash
sudo -u dshield_prism .venv/bin/python -m enrich.cli healthcheck
sudo -u dshield_prism .venv/bin/python -m enrich.cli enrich
```

The systemd timers (`dshield_prism-forward.timer` every 30 min;
`dshield_prism-backward.timer` every 6 h) handle steady-state. See
[docs/reference.md](docs/reference.md#systemd-cadence).

## Investigation console

Read-only browser GUI in [`console/`](console/). Search any IOC (IP, session
id, command sha, playbook, campaign, MITRE id, ASN, country) and pivot
through the resulting graph. See [console/README.md](console/README.md).

## Documentation

| Doc | What's in it |
|---|---|
| [docs/reference.md](docs/reference.md) | Operational notes, CLI, ECS schemas, tunables, intel subsystem, deploy recipes |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Open work |
| [docs/history/](docs/history/) | Per-phase shipped behaviour + design archive |

## License

See [LICENSE](LICENSE).
