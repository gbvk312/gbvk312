#!/usr/bin/env python3
import unittest
import os
import sys
import json
import ast
import re

# Add scripts directory to sys.path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
scripts_dir = os.path.join(repo_root, "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

import security_sentinel
import update_profile

class TestSecuritySentinel(unittest.TestCase):
    """Tests for repository security sentinel scanner."""

    def test_secret_detection_patterns(self):
        # Dynamically constructed test tokens to avoid static regex matches on test source
        dummy_gh_classic = "ghp_" + "1" * 36
        dummy_aws_key = "AKIA" + "A" * 16
        dummy_anthropic = "sk-ant-" + "a" * 35
        dummy_openai = "sk-" + "b" * 48
        dummy_slack_webhook = "https://hooks.slack.com/services/T12345678/B12345678/" + "c" * 24

        sample_text = f"""
        # Configuration
        GITHUB_TOKEN = "{dummy_gh_classic}"
        AWS_ACCESS_KEY = "{dummy_aws_key}"
        CLAUDE_KEY = "{dummy_anthropic}"
        OPENAI_KEY = "{dummy_openai}"
        SLACK = "{dummy_slack_webhook}"
        """

        detected_types = []
        for name, pattern in security_sentinel.SECRET_PATTERNS.items():
            if re.search(pattern, sample_text):
                detected_types.append(name)

        self.assertIn("GitHub Token (Classic)", detected_types)
        self.assertIn("AWS Access Key ID", detected_types)
        self.assertIn("Anthropic API Key", detected_types)
        self.assertIn("OpenAI API Key", detected_types)
        self.assertIn("Slack Webhook URL", detected_types)

    def test_benign_text_no_false_positives(self):
        benign_text = """
        def fetch_repos():
            return "https://github.com/gbvk312/multi-agent-orchestrator"
        user_uuid = "123e4567-e89b-12d3-a456-426614174000"
        """
        for name, pattern in security_sentinel.SECRET_PATTERNS.items():
            matches = list(re.finditer(pattern, benign_text))
            self.assertEqual(len(matches), 0, f"False positive for {name}: {matches}")

    def test_ast_vulnerability_auditor(self):
        unsafe_code = """
import subprocess
import pickle
import tempfile

eval("2 + 2")
exec("import os")
subprocess.run("ls -la", shell=True)
pickle.loads(b"data")
tempfile.mktemp()
"""
        tree = ast.parse(unsafe_code)
        auditor = security_sentinel.PythonSecurityAuditor("test_file.py")
        auditor.visit(tree)

        vuln_types = [v["type"].lower() for v in auditor.vulnerabilities]
        self.assertTrue(any("eval" in t for t in vuln_types))
        self.assertTrue(any("exec" in t for t in vuln_types))
        self.assertTrue(any("subprocess" in t for t in vuln_types))
        self.assertTrue(any("pickle" in t for t in vuln_types))
        self.assertTrue(any("tempfile" in t for t in vuln_types))

    def test_safe_python_code_passes(self):
        safe_code = """
import subprocess
import json

def run_task():
    result = subprocess.run(["git", "status"], stdout=subprocess.PIPE)
    return json.loads("{}")
"""
        tree = ast.parse(safe_code)
        auditor = security_sentinel.PythonSecurityAuditor("safe_file.py")
        auditor.visit(tree)
        self.assertEqual(len(auditor.vulnerabilities), 0)

    def test_repository_audit_is_clean(self):
        """Validates that the current codebase passes the security sentinel with zero issues."""
        report = security_sentinel.run_audit(root_dir=repo_root, save_report=False, display_results=False)
        self.assertEqual(report["status"], "PASSING")
        self.assertEqual(report["secrets_found"], 0)
        self.assertEqual(report["vulnerabilities_found"], 0)

class TestProfileUpdater(unittest.TestCase):
    """Tests for profile updater logic and README template replacements."""

    def test_safe_replace_utility(self):
        template = "<!-- TEST_START -->OLD<!-- TEST_END -->"
        pattern = r"(<!-- TEST_START -->\s*).*?(\s*<!-- TEST_END -->)"
        replaced = update_profile.safe_replace(pattern, "NEW_CONTENT", template)
        self.assertIn("NEW_CONTENT", replaced)
        self.assertNotIn("OLD", replaced)

    def test_markdown_and_html_escaping(self):
        # Test HTML escaping of issue title
        raw_issue_title = "<script>alert('xss')</script> & 'Attack'"
        escaped_title = update_profile.html.escape(raw_issue_title)
        self.assertNotIn("<script>", escaped_title)
        self.assertIn("&lt;script&gt;", escaped_title)
        self.assertIn("&amp;", escaped_title)

        # Test pipe character escaping in markdown tables
        raw_desc = "Fast tool for A | B testing"
        sanitized_desc = raw_desc.replace("|", "\\|")
        self.assertIn("A \\| B", sanitized_desc)

    def test_readme_markers_exist(self):
        readme_path = os.path.join(repo_root, "README.md")
        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_markers = [
            "REPO_BADGE",
            "TELECOM_BADGE",
            "UTILITY_BADGE",
            "FOCUS_SECTION",
            "SYSTEM_STATUS",
            "SECURITY_SENTINEL",
            "UTILITY_SPOTLIGHT"
        ]

        for marker in required_markers:
            start_tag = f"<!-- {marker}_START -->"
            end_tag = f"<!-- {marker}_END -->"
            self.assertIn(start_tag, content, f"Missing start tag: {start_tag}")
            self.assertIn(end_tag, content, f"Missing end tag: {end_tag}")

class TestDataIntegrity(unittest.TestCase):
    """Tests to verify repository data files are well-formed."""

    def test_data_files_valid_json(self):
        data_dir = os.path.join(repo_root, "data")
        expected_files = [
            ("repos.json", list),
            ("telecom_repos.json", list),
            ("utility_repos.json", list),
            ("security_report.json", dict)
        ]

        for fname, expected_type in expected_files:
            fpath = os.path.join(data_dir, fname)
            self.assertTrue(os.path.exists(fpath), f"File {fname} does not exist.")
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIsInstance(data, expected_type, f"{fname} root is not {expected_type}")
            self.assertTrue(len(data) > 0, f"{fname} is empty")

if __name__ == "__main__":
    unittest.main()
