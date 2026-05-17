"""Intel provider implementations.

Each provider is a single module under this package exposing a
`Provider` subclass. New providers slot in additively — the artifact
queue + writer don't need to change. See `base.py` for the contract.
"""
