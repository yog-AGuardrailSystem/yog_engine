"""Extractors turn raw tool arguments into typed facts a policy can reason about.

Policies are only as good as the facts they see: ``DROP TABLE`` hidden in a comment, ``rm -rf`` split by
quoting or ``/work/../etc`` all have to be resolved *before* the policy runs.  Every extractor returns a
nested dict that the gateway merges into the request's ``args`` (objects become dotted keys, lists become
one fact per element).  Each reports ``parsed``; when it is false the input could not be understood and a
policy should treat it as untrusted.
"""
from . import http, k8s, shell, sql

EXTRACTORS = {"sql": sql.extract, "shell": shell.extract, "http": http.extract, "k8s": k8s.extract}


def extract(kind: str, arguments: dict, field: str) -> dict:
    """Runs one extractor.  An unknown kind raises, so a typo in configuration cannot silently skip analysis."""
    return EXTRACTORS[kind](arguments, field)
