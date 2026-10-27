import pytest
from pathlib import Path

from yog import load_policy, YogError, Parser, tokenize, Engine


PROJECT_DIR = Path(__file__).parent
EXAMPLES_FILE = PROJECT_DIR / "all_examples.yog"


@pytest.fixture(scope="module")
def engine():
    """Load the team's policy examples."""
    return load_policy(str(EXAMPLES_FILE))


# ============================================================
# GROUPS A-H: REGRESSION TESTS
# ============================================================

@pytest.mark.parametrize(
    "actor, action, resource, expected",
    [
        # Group A: Admin-only delete
        ("a_agent", "can_delete", "database_1", "DENY"),
        ("a_admin", "can_delete", "database_1", "ALLOW"),

        # Group B: Role + environment
        ("b_agent", "can_deploy", "database_2", "ALLOW"),
        ("b_agent", "can_deploy", "payments_service", "DENY"),

        # Group C: Ownership-based
        ("c_finance_user", "can_modify", "c_database_1", "ALLOW"),

        # Group D: Combined AND policy
        ("d_admin", "can_delete_prod", "d_database_1", "ALLOW"),

        # Group E: Read a file
        ("e_agent", "can_read", "passwd_file", "DENY"),

        # Group F: Send email
        ("f_agent", "can_send_email", "external_addr", "DENY"),
        ("f_agent", "can_send_email", "internal_addr", "ALLOW"),

        # Group G: Modify configuration
        ("g_agent", "can_update_config", "app_yaml", "ALLOW"),

        # Group H: Create a user
        ("h_agent", "can_create_user", "engineering", "DENY"),
        ("h_agent", "can_create_user", "facilities", "ALLOW"),
    ],
)
def test_example_decision(engine, actor, action, resource, expected):
    """Verify that every existing example produces its expected decision."""
    result = engine.check(actor, action, resource)

    assert result["decision"] == expected, (
        f"{action}({actor}, {resource}): "
        f"expected {expected}, got {result['decision']}"
    )


# ============================================================
# FAILURE-CASE TESTS
# ============================================================

def test_rejects_rule_cycle():
    """The checker must reject recursive rule dependencies."""
    source = """
fact seed(a)

rule first(X):
    second(X)

rule second(X):
    first(X)
"""

    with pytest.raises(YogError, match="rule cycle"):
        Engine(Parser(tokenize(source)).parse())


def test_rejects_unsafe_negation():
    """Negation must not introduce an unbound variable."""
    source = """
fact known(a)

rule result(a):
    not known(X)
"""

    with pytest.raises(YogError, match="unbound variable"):
        Engine(Parser(tokenize(source)).parse())


def test_rejects_undefined_predicate():
    """Every predicate used in a rule must be defined."""
    source = """
rule result(X):
    missing(X)
"""

    with pytest.raises(YogError, match="not defined"):
        Engine(Parser(tokenize(source)).parse())


def test_rejects_predicate_role_conflict():
    """A predicate cannot be both a fact and a decision."""
    source = """
fact action(a)
fact known(a)

allow action(X):
    known(X)
"""

    with pytest.raises(YogError, match="both a fact and a decision"):
        Engine(Parser(tokenize(source)).parse())



