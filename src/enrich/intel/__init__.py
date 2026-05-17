"""External threat-intel enrichment subsystem.

Runs alongside the existing per-source enrichment pipeline. Looks up
*artifacts* (IPs, URLs, domains, hashes) against external feeds
(GreyNoise, AbuseIPDB, URLhaus, Spamhaus, Tor, ISC, ...) and writes
the results to project-owned `intel-<kind>-default` indices. Designed
to be additive — nothing here mutates existing enrichment docs.

See docs/ROADMAP.md "Research-mode strategic gaps" section A for the
provider roadmap and `docs/ROADMAP.md` "How free-tier limits reshape
the architecture" for the priority-queue design rationale.
"""
