# YOG Engine — Python Packaging and Testing Guide

## 1. Overview

YOG Engine is a lightweight, deterministic policy engine that checks whether an AI agent or application is allowed to perform an action.

It evaluates predefined policies and returns an authorization decision with a reason and evaluation trace.

## 2. Requirements

- Python 3.10 or later
- Git

## 3. Installation

### Step 1: Clone the repository

```powershell
git clone https://github.com/yog-AGuardrailSystem/yog_engine.git
cd yog_engine
```

### Step 2: Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install the package

```powershell
python -m pip install -e .
```

This installs YOG Engine in editable mode, allowing Python to use the local source code.

## 4. Verify the Installation

Run:

```powershell
python -c "import yog; print(callable(yog.load_policy))"
```

Expected output:

```text
True
```

**Explanation:** This confirms that the `yog` module can be imported and that the `load_policy()` function is available.

## 5. Test Authorization

The following tests were executed successfully during packaging validation.

### Test 1: Admin authorization

```powershell
python -c "import yog; e=yog.load_policy('all_examples.yog'); print(e.check('a_admin','can_delete','database_1'))"
```

Expected output:

```python
{
    'decision': 'ALLOW',
    'reason': 'allow clause at line 9 matched',
    'trace': [
        '?- role(a_admin, admin)',
        '  matched fact role(a_admin, admin)'
    ]
}
```

**Explanation:** The request is allowed because the policy contains the fact that `a_admin` has the `admin` role, satisfying the applicable allow rule.

### Test 2: Agent authorization

```powershell
python -c "import yog; e=yog.load_policy('all_examples.yog'); print(e.check('a_agent','can_delete','database_1'))"
```

Expected output:

```python
{
    'decision': 'DENY',
    'reason': 'default deny: no allow clause was satisfied',
    'trace': []
}
```

**Explanation:** The request is denied because no applicable allow rule was satisfied for `a_agent`.

These tests demonstrate both an allowed and a denied authorization request.

## 6. Understanding the API

The main API used in the tests is:

```python
import yog

engine = yog.load_policy("all_examples.yog")

result = engine.check(
    "a_admin",
    "can_delete",
    "database_1"
)

print(result["decision"])
print(result["reason"])
print(result["trace"])
```

The `check()` method accepts:

- **Actor:** The user or agent requesting an action.
- **Action:** The operation being requested.
- **Resource:** The target of the operation.

It returns a dictionary containing:

- `decision` — the authorization result (`ALLOW` or `DENY`).
- `reason` — an explanation of the decision.
- `trace` — details of the policy evaluation.

## 7. Run the Example Policies

From the repository directory, execute:

```powershell
python yog.py all_examples.yog
```

This runs the queries included in `all_examples.yog` and prints their results.

The example policies cover scenarios such as role-based deletion, deployment restrictions, resource ownership, email restrictions, file uploads, and API access.

## 8. Package Information

- **Package name:** `yog-engine`
- **Version:** `0.1.0`
- **Python import name:** `yog`
- **Packaging configuration:** `pyproject.toml`
- **Installation mode:** Editable installation

The `pyproject.toml` file defines the package metadata and configures installation of the existing `yog.py` module.

## 9. Validation Status

The following checks were completed successfully in the team repository:

- Package installation using `python -m pip install -e .`
- Import verification
- Admin authorization test returning `ALLOW`
- Agent authorization test returning `DENY`
- Execution of the supplied example policy file

These results validate the tested packaging and authorization workflows. They do not represent complete automated test-suite coverage.

## Command-Line Demo (CLI)

The YOG CLI provides a simple way to run authorization checks against a `.yog` policy file without writing additional Python code.

### Requirements

- Python 3.10 or later
- The YOG Engine repository
- The existing `all_examples.yog` policy file

### 1. Install the package

From the repository root, run:

```powershell
python -m pip install -e .
```

### 2. Display CLI help

```powershell
python .\yog_cli.py --help
```

### 3. Run the predefined demo

```powershell
python .\yog_cli.py --demo
```

The demo checks four authorization scenarios: an administrator deleting a database, a developer attempting the same action, and deployment requests to permitted and restricted resources.

### 4. Run a custom authorization check

```powershell
python .\yog_cli.py --actor a_admin --action can_delete --resource database_1
```

The CLI displays the decision, reason, and evaluation trace.

### 5. Display the full evaluation trace

```powershell
python .\yog_cli.py --actor a_admin --action can_delete --resource database_1 --trace
```

### 6. Select another policy file

```powershell
python .\yog_cli.py --policy path\to\policy.yog --demo
```

Replace the path with the location of your policy file.

### 7. Run the CLI regression tests

```powershell
python -m unittest discover -s tests -v
```

The current CLI test suite covers help output, demo decisions, custom authorization checks, and missing policy files.

### CLI options

| Option | Purpose |
|---|---|
| `--policy` | Select the policy file |
| `--actor` | Specify the requesting actor |
| `--action` | Specify the action to check |
| `--resource` | Specify the target resource |
| `--trace` | Display the detailed result and trace |
| `--demo` | Run predefined authorization examples |
| `--help` | Display usage instructions |

**Note:** This CLI is a demonstration interface for the Python reference engine. It does not yet provide integration with the C library.
