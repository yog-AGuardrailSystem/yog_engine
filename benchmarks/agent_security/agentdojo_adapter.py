"""AgentDojo integration.

Two pieces:

* :func:`facts_for_environment` derives the trusted facts a policy may use
  (known payees, contacts, users) from the suite's *environment*, never from
  the agent's arguments.
* :func:`guarded_runtime_class` returns a ``FunctionsRuntime`` subclass that
  asks YOG before every tool call.  AgentDojo's ``TaskSuite.run_task_with_pipeline``
  accepts a ``runtime_class``, so a live run uses the guard with one argument:

      suite.run_task_with_pipeline(pipeline, user_task, injection_task,
                                   injections, runtime_class=GuardedRuntime)

  Nested function calls are guarded too, because the base runtime resolves them
  through ``self.run_function``.

AgentDojo is an optional dependency.  Import this module only when it is
installed; the offline evaluator does, and the unit tests use stand-ins.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .guard import Decision, ToolGuard

_URL_RE = re.compile(r"(?:https?://)?(?:www\.)?[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}")


def _host_from_url(value: str) -> str:
    """Return the lower-case host of a URL or bare domain, or ``""``."""
    text = value.strip()
    if not text:
        return ""
    candidate = text if "://" in text else "//" + text
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".,;:!?)")


def _domains_in_text(text: str) -> set[str]:
    domains: set[str] = set()
    for match in _URL_RE.findall(text):
        host = _host_from_url(match)
        if host:
            domains.add(host)
    return domains


def _emails_from_mailbox(inbox: dict) -> set[str]:
    addresses: set[str] = set()
    account = inbox.get("account_email")
    if isinstance(account, str):
        addresses.add(account)
    for contact in inbox.get("contact_list") or []:
        if isinstance(contact, dict) and isinstance(contact.get("email"), str):
            addresses.add(contact["email"])
    for message in inbox.get("initial_emails") or []:
        if not isinstance(message, dict):
            continue
        for field in ("sender", "recipients", "cc", "bcc"):
            value = message.get(field)
            if isinstance(value, str):
                addresses.add(value)
            elif isinstance(value, list):
                addresses.update(item for item in value if isinstance(item, str))
    return addresses


def facts_for_environment(suite: str, env: Any) -> list[tuple[str, tuple]]:
    """Trusted facts for ``suite``, derived from the AgentDojo environment."""
    data = env.model_dump() if hasattr(env, "model_dump") else dict(env)
    facts: list[tuple[str, tuple]] = []

    if suite == "banking":
        account = data.get("bank_account") or {}
        own = account.get("iban")
        if isinstance(own, str):
            facts.append(("trusted_recipient", (own,)))
        for transaction in (account.get("transactions") or []) + (account.get("scheduled_transactions") or []):
            if not isinstance(transaction, dict):
                continue
            for field in ("sender", "recipient"):
                value = transaction.get(field)
                if isinstance(value, str) and value != "me":
                    facts.append(("trusted_recipient", (value,)))

    elif suite == "workspace":
        inbox = data.get("inbox") or {}
        addresses = _emails_from_mailbox(inbox)
        calendar = data.get("calendar") or {}
        for event in calendar.get("initial_events") or []:
            if isinstance(event, dict):
                for participant in event.get("participants") or []:
                    if isinstance(participant, str):
                        addresses.add(participant)
        drive = data.get("cloud_drive") or {}
        for file in drive.get("initial_files") or []:
            if not isinstance(file, dict):
                continue
            owner = file.get("owner")
            if isinstance(owner, str):
                addresses.add(owner)
            for share in file.get("shared_with") or []:
                if isinstance(share, dict) and isinstance(share.get("email"), str):
                    addresses.add(share["email"])
                elif isinstance(share, str):
                    addresses.add(share)
        facts.extend(("known_email", (address,)) for address in sorted(addresses))

    elif suite == "slack":
        slack = data.get("slack") or {}
        for user in slack.get("users") or []:
            if isinstance(user, str):
                facts.append(("known_user", (user,)))
        # Domains mentioned in the workspace's own mail and channels are
        # trusted; a lookalike or attacker domain is not in this set.
        domains: set[str] = set()
        for inbox_key in ("user_inbox", "channel_inbox"):
            inbox = slack.get(inbox_key) or {}
            if not isinstance(inbox, dict):
                continue
            for messages in inbox.values():
                if not isinstance(messages, list):
                    continue
                for message in messages:
                    if isinstance(message, dict) and isinstance(message.get("body"), str):
                        domains.update(_domains_in_text(message["body"]))
        facts.extend(("known_domain", (domain,)) for domain in sorted(domains))
        # A user who has been invited but is not in the workspace yet is still a
        # name the policy may want to see; the environment's users list is the
        # authority for "known", so invited-only users go through approval.

    elif suite == "travel":
        inbox = data.get("inbox") or {}
        facts.extend(("known_email", (address,)) for address in sorted(_emails_from_mailbox(inbox)))

    return facts


def facts_for_call(suite: str, env: Any, function: str,
                   arguments: Mapping[str, Any]) -> list[tuple[str, tuple]]:
    """Environment facts plus per-call URL provenance.

    ``url_domain("input.url", Host)`` lets a policy compare the host a tool is
    about to visit with the workspace's ``known_domain`` facts.  The agent
    controls the URL, so this fact is only a projection of its argument, not a
    trust signal by itself.
    """
    facts = list(facts_for_environment(suite, env)) if env is not None else []
    if isinstance(arguments, Mapping):
        for name in ("url", "href", "link"):
            value = arguments.get(name)
            if isinstance(value, str):
                host = _host_from_url(value)
                if host:
                    facts.append(("url_domain", (f"input.{name}", host)))
    return facts


def guarded_runtime_class(suite: str, guard: ToolGuard, decisions: list | None = None):
    """Return a ``FunctionsRuntime`` subclass that consults ``guard``.

    The class is built lazily so importing this module does not require
    AgentDojo.  The runtime recomputes facts from the environment on each call,
    so a tool that changes the environment (for example, adding a contact) is
    reflected in the next decision.

    If ``decisions`` is a list, every :class:`Decision` is appended to it so a
    live runner can report per-call counts without changing the policy.
    """
    from agentdojo.functions_runtime import FunctionsRuntime

    class GuardedRuntime(FunctionsRuntime):
        def run_function(self, env, function, kwargs, raise_on_error=False):
            decision: Decision = guard.check(
                function, dict(kwargs),
                facts=facts_for_call(suite, env, function, dict(kwargs)) if env is not None else (),
            )
            if decisions is not None:
                decisions.append(decision)
            if decision.blocked:
                message = f"PolicyBlocked: {decision.decision}: {decision.reason}"
                if raise_on_error:
                    raise PermissionError(message)
                return "", message
            result = super().run_function(env, function, kwargs, raise_on_error)
            output, error = result if isinstance(result, tuple) and len(result) == 2 else (result, None)
            if error is None:
                # Cross-step information flow: a source tool's output becomes
                # tainted values that later calls are checked against.
                guard.observe(function, output)
            return result

    GuardedRuntime.__name__ = f"YogGuarded{suite.title()}Runtime"
    return GuardedRuntime


def run_live_task(suite, pipeline, guard: ToolGuard, user_task, injection_task, injections,
                  environment=None):
    """Run one AgentDojo task with the guard installed (used by ``--live``).

    This is the public-API equivalent of ``benchmark_suite_with_injections``
    for a single task; it exists because the helper does not expose
    ``runtime_class``.
    """
    return suite.run_task_with_pipeline(
        pipeline, user_task, injection_task, injections,
        runtime_class=guarded_runtime_class(suite.name, guard),
        environment=environment,
    )


def load_environment(suite, injections: Iterable | None = None):
    """Small wrapper so callers do not have to remember the empty-dict default."""
    return suite.load_and_inject_default_environment(dict(injections or {}))
