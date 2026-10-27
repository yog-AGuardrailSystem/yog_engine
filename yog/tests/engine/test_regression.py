
from pathlib import Path

from yog import load_policy
from yog import Atom, Const


PROJECT_DIR = Path(__file__).resolve().parents[1]
POLICY_FILE = PROJECT_DIR / "all_examples.yog"


def test_group_a_developer_cannot_delete_database():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "a_agent",
        "can_delete",
        "database_1",
    )

    assert result["decision"] == "DENY"


def test_group_a_admin_can_delete_database():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "a_admin",
        "can_delete",
        "database_1",
    )

    assert result["decision"] == "ALLOW"

    
def test_group_b_agent_can_deploy_database():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "b_agent",
        "can_deploy",
        "database_2",
    )

    assert result["decision"] == "ALLOW"


def test_group_b_agent_cannot_deploy_payments_service():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "b_agent",
        "can_deploy",
        "payments_service",
    )

    assert result["decision"] == "DENY"


def test_group_c_finance_user_can_modify_database():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "c_finance_user",
        "can_modify",
        "c_database_1",
    )

    assert result["decision"] == "ALLOW"


def test_group_d_admin_can_delete_production_database():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "d_admin",
        "can_delete_prod",
        "d_database_1",
    )

    assert result["decision"] == "ALLOW"
    
def test_group_e_agent_cannot_read_password_file():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "e_agent",
        "can_read",
        "passwd_file",
    )

    assert result["decision"] == "DENY"


def test_group_f_agent_cannot_email_external_address():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "f_agent",
        "can_send_email",
        "external_addr",
    )

    assert result["decision"] == "DENY"


def test_group_f_agent_can_email_internal_address():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "f_agent",
        "can_send_email",
        "internal_addr",
    )

    assert result["decision"] == "ALLOW"

def test_group_g_agent_can_update_config():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "g_agent",
        "can_update_config",
        "app_yaml",
    )

    assert result["decision"] == "ALLOW"


def test_group_h_agent_cannot_create_engineering_user():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "h_agent",
        "can_create_user",
        "engineering",
    )

    assert result["decision"] == "DENY"


def test_group_h_agent_can_create_facilities_user():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "h_agent",
        "can_create_user",
        "facilities",
    )

    assert result["decision"] == "ALLOW"


def test_group_i_transfer_within_limit_is_allowed():
    eng = load_policy(str(POLICY_FILE))

    context = [
        Atom("amount", [Const("i_acct_999"), Const(9000)])
    ]

    result = eng.check(
        "i_customer",
        "can_transfer",
        "i_acct_999",
        context=context,
    )

    assert result["decision"] == "ALLOW"


def test_group_i_transfer_over_limit_is_denied():
    eng = load_policy(str(POLICY_FILE))

    context = [
        Atom("amount", [Const("i_acct_999"), Const(50000)])
    ]

    result = eng.check(
        "i_customer",
        "can_transfer",
        "i_acct_999",
        context=context,
    )

    assert result["decision"] == "DENY"

def test_group_j_agent_cannot_run_dangerous_command():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "j_agent",
        "can_run_command",
        "rm_rf",
    )

    assert result["decision"] == "DENY"


def test_group_j_sandboxed_agent_can_run_ls():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "j_sandboxed_agent",
        "can_run_command",
        "ls_command",
    )

    assert result["decision"] == "ALLOW"


def test_group_k_agent_cannot_upload_pdf():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "k_agent",
        "can_upload",
        "report_pdf",
    )

    assert result["decision"] == "DENY"


def test_group_k_agent_can_upload_text_file():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "k_agent",
        "can_upload",
        "notes_txt",
    )

    assert result["decision"] == "ALLOW"

def test_group_l_agent_can_call_allowed_api():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "l_agent",
        "can_call_api",
        "allowed_api",
    )

    assert result["decision"] == "ALLOW"


def test_group_l_agent_cannot_call_blocked_api():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "l_agent",
        "can_call_api",
        "blocked_api",
    )

    assert result["decision"] == "DENY"


def test_group_m_agent_cannot_delete_config_file():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "m_agent",
        "can_delete_file",
        "config_yaml",
    )

    assert result["decision"] == "DENY"


def test_group_n_agent_cannot_modify_admin_database():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "n_agent",
        "can_modify_admin",
        "database_1",
    )

    assert result["decision"] == "DENY"

def test_group_o_agent_cannot_deploy_payments_release():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "o_agent",
        "can_deploy_release",
        "payments_svc",
    )

    assert result["decision"] == "DENY"


def test_group_p_agent_cannot_read_payroll_file():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "p_agent",
        "can_read_sensitive",
        "payroll_csv",
    )

    assert result["decision"] == "DENY"

def test_group_q_agent_cannot_call_refund_endpoint():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "q_agent",
        "can_call_payment",
        "refund_endpoint",
    )

    assert result["decision"] == "DENY"


def test_group_r_alice_can_access_normal_document():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "r_alice",
        "can_access",
        "normal_doc",
    )

    assert result["decision"] == "ALLOW"


def test_group_r_alice_cannot_access_payroll_document():
    eng = load_policy(str(POLICY_FILE))

    result = eng.check(
        "r_alice",
        "can_access",
        "payroll_doc",
    )

    assert result["decision"] == "DENY"

def test_rule_cycle_is_rejected(tmp_path):
    from yog import YogError

    policy = tmp_path / "cycle.yog"
    policy.write_text(
        "rule a(X):\n"
        "    b(X)\n"
        "rule b(X):\n"
        "    a(X)\n"
        "allow access(X):\n"
        "    a(X)\n"
    )

    try:
        load_policy(str(policy))
        assert False, "Expected YogError for rule cycle"
    except YogError as exc:
        assert "rule cycle:" in str(exc)

        
def test_unsafe_negation_is_rejected(tmp_path):
    from yog import YogError

    policy = tmp_path / "unsafe_negation.yog"
    policy.write_text(
        "fact known(alice)\n"
        "fact person(alice)\n"
        "rule suspicious(X):\n"
        "    person(X)\n"
        "    not known(Y)\n"
        "allow access(X):\n"
        "    suspicious(X)\n"
    )

    

    try:
        load_policy(str(policy))
        assert False, "Expected YogError for unsafe negation"
    except YogError as exc:
        assert "unbound variable(s)" in str(exc)
        assert "inside `not`" in str(exc)


def test_undefined_predicate_is_rejected(tmp_path):
    from yog import YogError

    policy = tmp_path / "undefined_predicate.yog"
    policy.write_text(
        "allow access(X):\n"
        "    missing_permission(X)\n"
    )

    try:
        load_policy(str(policy))
        assert False, "Expected YogError for undefined predicate"
    except YogError as exc:
        assert "is not defined by any fact or rule" in str(exc)

def test_predicate_role_conflict_is_rejected(tmp_path):
    from yog import YogError

    policy = tmp_path / "role_conflict.yog"
    policy.write_text(
        "fact access(alice)\n"
        "allow access(X):\n"
        "    access(X)\n"
    )

    try:
        load_policy(str(policy))
        assert False, "Expected YogError for predicate-role conflict"
    except YogError as exc:
        assert "is both a fact and a decision head" in str(exc)
        assert "pick one role for it" in str(exc)
