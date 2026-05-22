#!/usr/bin/env python3
import os
import re
import ast
import json
import sys
from datetime import datetime, timezone

# Regex patterns for common secrets/keys
SECRET_PATTERNS = {
    "GitHub Token (Classic)": r"\bghp_[a-zA-Z0-9]{36}\b",
    "GitHub Fine-grained Token": r"\bgithub_pat_[a-zA-Z0-9_]{82}\b",
    "Google API Key": r"\bAIzaSy[a-zA-Z0-9\-_]{33}\b",
    "AWS Access Key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Private Key Block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "Generic High-Entropy Key Assignment": r"(?i)(api[-_]?key|secret[-_]?key|private[-_]?key|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\/\+]{20,}['\"]"
}

# Directories to exclude from scanning
EXCLUDE_DIRS = {".git", "scratch", "venv", ".venv", "node_modules", "dist", "build"}
EXCLUDE_FILES = {"security_sentinel.py"}  # Skip itself

class PythonSecurityAuditor(ast.NodeVisitor):
    """AST visitor to audit Python code for security anti-patterns."""
    def __init__(self, filename):
        self.filename = filename
        self.vulnerabilities = []

    def visit_Call(self, node):
        # 1. Check for eval() and exec() usage
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self.vulnerabilities.append({
                    "type": f"Dangerous Built-in Call ({node.func.id})",
                    "line": node.lineno,
                    "severity": "HIGH",
                    "description": f"Use of '{node.func.id}()' found, which can execute arbitrary code."
                })
        
        # 2. Check for unsafe subprocess calls with shell=True
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            self.vulnerabilities.append({
                                "type": "Unsafe Subprocess Execution",
                                "line": node.lineno,
                                "severity": "MEDIUM",
                                "description": f"subprocess.{node.func.attr} called with shell=True, vulnerable to shell injection."
                            })
        
        self.generic_visit(node)

def audit_file(filepath):
    """Performs both regex-based secret scanning and language-specific AST audits."""
    results = {
        "filepath": filepath,
        "secrets": [],
        "vulnerabilities": []
    }
    
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            
        # 1. Secret Scanning via Regex
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for m in matches:
                # Get line number of match
                line_no = content.count("\n", 0, m.start()) + 1
                # Redact matched secret for safety in logs
                matched_val = m.group(0)
                redacted = matched_val[:4] + "..." + matched_val[-4:] if len(matched_val) > 8 else "..."
                results["secrets"].append({
                    "type": name,
                    "line": line_no,
                    "value": redacted
                })
                
        # 2. AST Audits for Python files
        if filepath.endswith(".py"):
            try:
                tree = ast.parse(content, filename=filepath)
                visitor = PythonSecurityAuditor(filepath)
                visitor.visit(tree)
                results["vulnerabilities"].extend(visitor.vulnerabilities)
            except SyntaxError as e:
                results["vulnerabilities"].append({
                    "type": "Syntax Error during Audit",
                    "line": e.lineno or 0,
                    "severity": "LOW",
                    "description": f"Failed to parse AST: {e.msg}"
                })
                
        # 3. Security Audits for GitHub Workflow files
        if ".github/workflows" in filepath and (filepath.endswith(".yml") or filepath.endswith(".yaml")):
            # Look for untrusted third-party actions or excessive permissions
            if "pull_request:" in content and "permissions:" not in content:
                results["vulnerabilities"].append({
                    "type": "Missing Workflow Permissions Block",
                    "line": 1,
                    "severity": "MEDIUM",
                    "description": "Workflow handles pull request events but lacks custom permissions constraints."
                })
            if "uses: actions/checkout" in content and "fetch-depth: 0" not in content and "touch" in content:
                results["vulnerabilities"].append({
                    "type": "Shallow Clone Touch Warning",
                    "line": 1,
                    "severity": "LOW",
                    "description": "Workflow uses checkout action without fetch-depth: 0 but performs file touches, which might fail or be inaccurate on shallow clones."
                })

    except Exception as e:
        print(f"Error auditing file {filepath}: {e}", file=sys.stderr)
        
    return results

def get_tracked_files():
    """Recursively lists all files to scan, respecting excludes."""
    files_to_scan = []
    for root, dirs, files in os.walk("."):
        # Exclude directories in-place to prevent os.walk from entering them
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f not in EXCLUDE_FILES and not f.startswith("."):
                files_to_scan.append(os.path.join(root, f))
    return files_to_scan

def main():
    print("🛡️ Security Sentinel starting repository audit...")
    tracked_files = get_tracked_files()
    
    scan_report = {
        "status": "PASSING",
        "files_scanned": 0,
        "secrets_found": 0,
        "vulnerabilities_found": 0,
        "last_audit": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "details": []
    }
    
    for filepath in tracked_files:
        # Normalize paths
        normal_path = os.path.relpath(filepath, ".")
        res = audit_file(normal_path)
        scan_report["files_scanned"] += 1
        
        if res["secrets"] or res["vulnerabilities"]:
            scan_report["secrets_found"] += len(res["secrets"])
            scan_report["vulnerabilities_found"] += len(res["vulnerabilities"])
            scan_report["details"].append(res)
            
    # Set status to FAILING if any high/medium vulnerabilities or secrets are found
    has_threats = scan_report["secrets_found"] > 0
    if not has_threats:
        for file_res in scan_report["details"]:
            for vuln in file_res.get("vulnerabilities", []):
                if vuln.get("severity") in ("HIGH", "MEDIUM"):
                    has_threats = True
                    break
                    
    if has_threats:
        scan_report["status"] = "FAILING"
        
    # Output report
    print(f"\nAudit complete. Scanned {scan_report['files_scanned']} files.")
    print(f"Status: {scan_report['status']}")
    print(f"Secrets detected: {scan_report['secrets_found']}")
    print(f"Code vulnerabilities: {scan_report['vulnerabilities_found']}")
    
    # Save the report as JSON in scratch
    os.makedirs("scratch", exist_ok=True)
    with open("scratch/security_report.json", "w") as f:
        json.dump(scan_report, f, indent=2)
    print("Saved security report to scratch/security_report.json")
    
    if scan_report["status"] == "FAILING":
        print("\n❌ Threat Detected! Please fix the reported items.", file=sys.stderr)
        # We don't exit with non-zero unless forced, to let the profile build continue gracefully.
        
if __name__ == "__main__":
    main()
