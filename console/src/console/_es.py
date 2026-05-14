"""Read-only Elasticsearch client factory.

DUPLICATION NOTICE: `make_client` is duplicated from
`src/enrich/es_client.py`. Kept separate so the console has no
Python dependency on the parent package. If the auth-precedence rules
(api_key over basic_auth) change in the parent, mirror them here.
"""
from __future__ import annotations

from elasticsearch import Elasticsearch

from ._config import ESConfig, Secrets


def make_client(cfg: ESConfig, secrets: Secrets) -> Elasticsearch:
    # Mirror the parent package's noise-suppression when the user has
    # explicitly opted into unverified TLS. Silences both urllib3's per-
    # request `InsecureRequestWarning` and the elasticsearch client's
    # one-shot `SecurityWarning`. See src/enrich/es_client.py for
    # the rationale; the two helpers are intentionally duplicated so the
    # console package has no Python dependency on enrich.
    if not cfg.verify_certs:
        import warnings
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        try:
            from elasticsearch import SecurityWarning as _ESSecurityWarning
            warnings.filterwarnings("ignore", category=_ESSecurityWarning)
        except Exception:
            pass
        warnings.filterwarnings("ignore", message=r".*verify_certs=False.*")
    kwargs: dict = {
        "hosts": cfg.hosts,
        "verify_certs": cfg.verify_certs,
        "request_timeout": cfg.request_timeout,
    }
    if cfg.ca_certs:
        kwargs["ca_certs"] = cfg.ca_certs
    if secrets.es_api_key:
        kwargs["api_key"] = secrets.es_api_key
    elif secrets.es_username and secrets.es_password:
        kwargs["basic_auth"] = (secrets.es_username, secrets.es_password)
    else:
        raise RuntimeError(
            "No ES credentials. Set ES_USERNAME/ES_PASSWORD or ES_API_KEY in "
            ".env (or export them in the environment). The .env file is "
            "searched in this order: $PRISM_ENV, "
            "alongside-config-file's parent, alongside-config-file, CWD."
        )
    return Elasticsearch(**kwargs)
