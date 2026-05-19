"""Persisted findings index — M5.

Two rule kinds:

- `likely_discovery` — IP with high local novelty AND high external rarity.
  These are the candidates an analyst should look at first: the cluster
  geometry says "this attacker is unlike anything else in our corpus"
  AND external feeds say "we've never heard of them." Almost by
  definition, the discoveries the honeypot is set up to find.

- `axis_disagreement` — URL artifact whose consensus contradicts its
  host IP's consensus. URL flagged but host IP clean (hijacked legit
  infrastructure); URL clean but host IP flagged (suspicious site on
  a known-bad host). Either direction is worth investigating.

The miner runs hourly via systemd; the console reads the resulting
`prism.finding` index. Status workflow (`new` / `ack` /
`confirmed` / `rejected`) lives on each doc and is preserved across
re-mines.
"""
