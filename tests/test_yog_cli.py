
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "yog_cli.py"
POLICY = ROOT / "all_examples.yog"


class TestYogCLI(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--actor", result.stdout)
        self.assertIn("--demo", result.stdout)

    def test_demo(self):
        result = self.run_cli("--demo")
        self.assertEqual(result.returncode, 0)
        self.assertIn("a_admin -> can_delete(database_1): ALLOW", result.stdout)
        self.assertIn("a_agent -> can_delete(database_1): DENY", result.stdout)
        self.assertIn("b_agent -> can_deploy(database_2): ALLOW", result.stdout)
        self.assertIn("b_agent -> can_deploy(payments_service): DENY", result.stdout)

    def test_custom_allow(self):
        result = self.run_cli(
            "--actor", "a_admin",
            "--action", "can_delete",
            "--resource", "database_1",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn('"decision": "ALLOW"', result.stdout)

    def test_missing_policy(self):
        result = self.run_cli("--policy", "missing_file.yog", "--demo")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Policy file not found", result.stderr)


if __name__ == "__main__":
    unittest.main()