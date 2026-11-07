#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "rich",
# ]
# ///
import os
import re
import ast
import json
import sys
from datetime import datetime, timezone

# Graceful fallback for Rich to ensure zero-dependency portability
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.theme import Theme

    custom_theme = Theme({
        "info": "cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
    })
    console = Console(theme=custom_theme)
except ImportError:
    class Theme:
        def __init__(self, theme_dict=None):
            self.styles = theme_dict or {}

    class Panel:
        def __init__(self, renderable, title="", border_style=""):
            self.renderable = renderable
            self.title = title

        def __str__(self):
            clean_text = re.sub(r'\[/?[a-zA-Z0-9_\- ]+\]', '', str(self.renderable))
            lines = clean_text.splitlines()
            max_w = max((len(l) for l in lines), default=40)
            t_header = f" [ {self.title} ] " if self.title else ""
            w = max(max_w + 2, len(t_header) + 4, 46)
            top = f"┌{t_header}" + "─" * (w - len(t_header) - 1) + "┐"
            bot = "└" + "─" * (w - 1) + "┘"
            body = [f"│ {l:<{w-3}}│" for l in lines]
            return "\n".join([top] + body + [bot])

    class Table:
        def __init__(self, title="", show_header=True, header_style=""):
            self.title = title
            self.columns = []
            self.rows = []

        def add_column(self, name, style="", justify="left"):
            self.columns.append(name)

        def add_row(self, *cells):
            self.rows.append([str(c) for c in cells])

        def __str__(self):
            lines = [f"--- {self.title} ---"]
            if self.columns:
                lines.append(" | ".join(self.columns))
                lines.append("-" * 60)
            for r in self.rows:
                clean_row = [re.sub(r'\[/?[a-zA-Z0-9_\- ]+\]', '', c) for c in r]
                lines.append(" | ".join(clean_row))
            return "\n".join(lines)

    class Console:
        def __init__(self, theme=None):
            self.theme = theme

        def print(self, *args, **kwargs):
            file = kwargs.get("file", sys.stdout)
            clean_args = []
            for arg in args:
                if isinstance(arg, (Panel, Table)):
                    clean_args.append(str(arg))
                else:
                    clean_text = re.sub(r'\[/?[a-zA-Z0-9_\- ]+\]', '', str(arg))
                    clean_args.append(clean_text)
            print(*clean_args, file=file)

    console = Console()

# Regex patterns for common secrets/keys (DevSecOps Pattern Library)
SECRET_PATTERNS = {
    "GitHub Token (Classic)": r"\bghp_[a-zA-Z0-9]{36}\b",
    "GitHub OAuth Token": r"\bgho_[a-zA-Z0-9]{36}\b",
    "GitHub User / Server Token": r"\bgh[usr]_[a-zA-Z0-9]{36}\b",
    "GitHub Fine-grained Token": r"\bgithub_pat_[a-zA-Z0-9_]{82}\b",
    "Google API Key": r"\bAIzaSy[a-zA-Z0-9\-_]{33}\b",
    "AWS Access Key ID": r"\bAKIA[0-9A-Z]{16}\b",
    "Slack Webhook URL": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Private Key Block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "HuggingFace Token": r"\bhf_[a-zA-Z0-9]{34,}\b",
    "OpenAI API Key": r"\bsk-[a-zA-Z0-9]{48}\b",
    "OpenAI Project Key": r"\bsk-proj-[a-zA-Z0-9-]{48,96}\b",
    "Anthropic API Key": r"\bsk-ant-[a-zA-Z0-9\-_]{32,}\b",
    "Slack Token": r"\bxox[baprs]-[a-zA-Z0-9-]{10,48}\b",
    "Discord Bot Token": r"\b[a-zA-Z0-9_\-]{24}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,38}\b",
    "Stripe Secret Key": r"\bsk_live_[0-9a-zA-Z]{24}\b",
    "Generic High-Entropy Key Assignment": r"(?i)(api[-_]?key|secret[-_]?key|private[-_]?key|token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\/\+]{20,}['\"]"
}

# Directories and files to exclude from scanning
EXCLUDE_DIRS = {
    ".git", "data", "scratch", "venv", ".venv", "node_modules", "dist",
    "build", "__pycache__", ".pytest_cache", ".ruff_cache", "tests"
}
EXCLUDE_FILES = {"security_sentinel.py"}  # Skip itself to avoid matching its own pattern definitions
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".pyc"
}

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

            # 3. Check for insecure deserialization (pickle)
            elif node.func.attr in ("load", "loads"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                    self.vulnerabilities.append({
                        "type": "Insecure Deserialization (pickle)",
                        "line": node.lineno,
                        "severity": "HIGH",
                        "description": f"pickle.{node.func.attr}() found; deserializing untrusted data can lead to arbitrary code execution."
                    })

            # 4. Check for deprecated / race-condition tempfile usage
            elif node.func.attr == "mktemp":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile":
                    self.vulnerabilities.append({
                        "type": "Insecure Tempfile Usage",
                        "line": node.lineno,
                        "severity": "MEDIUM",
                        "description": "tempfile.mktemp() is deprecated and susceptible to race conditions. Use tempfile.NamedTemporaryFile() instead."
                    })

        self.generic_visit(node)

def audit_file(filepath):
    """Performs both regex-based secret scanning and language-specific AST audits."""
    results = {
        "filepath": filepath,
        "secrets": [],
        "vulnerabilities": []
    }

    # Skip binary files
    _, ext = os.path.splitext(filepath)
    if ext.lower() in BINARY_EXTENSIONS:
        return results

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # 1. Secret Scanning via Regex
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for m in matches:
                line_no = content.count("\n", 0, m.start()) + 1
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
        console.print(f"[danger]Error auditing file {filepath}: {e}[/danger]", file=sys.stderr)

    return results

def get_tracked_files(root_dir="."):
    """Recursively lists all files to scan, respecting excludes and skipping binary files."""
    files_to_scan = []
    for root, dirs, files in os.walk(root_dir):
        # Exclude directories in-place (exclude hidden dirs except .github)
        dirs[:] = [
            d for d in dirs
            if d not in EXCLUDE_DIRS and (not d.startswith(".") or d == ".github")
        ]
        for f in files:
            if f in EXCLUDE_FILES or f.startswith("."):
                continue
            _, ext = os.path.splitext(f)
            if ext.lower() in BINARY_EXTENSIONS:
                continue
            files_to_scan.append(os.path.join(root, f))
    return sorted(files_to_scan)

def run_audit(root_dir=".", save_report=True, display_results=True):
    """
    Executes the DevSecOps security scan across the repository.
    Can be imported programmatically or run via CLI.
    """
    if display_results:
        console.print(Panel(
            "[bold cyan]🛡️ Security Sentinel[/bold cyan]\n[dim]Starting repository security & credential audit...[/dim]",
            border_style="cyan"
        ))

    tracked_files = get_tracked_files(root_dir)

    scan_report = {
        "status": "PASSING",
        "files_scanned": 0,
        "secrets_found": 0,
        "vulnerabilities_found": 0,
        "last_audit": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "details": []
    }

    for filepath in tracked_files:
        normal_path = os.path.relpath(filepath, root_dir)
        res = audit_file(filepath)
        scan_report["files_scanned"] += 1

        if res["secrets"] or res["vulnerabilities"]:
            scan_report["secrets_found"] += len(res["secrets"])
            scan_report["vulnerabilities_found"] += len(res["vulnerabilities"])
            res["filepath"] = normal_path
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

    if display_results:
        if scan_report["details"]:
            table = Table(title="🔍 Detected Security Issues / Warnings", show_header=True, header_style="bold magenta")
            table.add_column("File Path", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Line", justify="right", style="green")
            table.add_column("Severity / Info", style="red")
            table.add_column("Description", style="white")

            for file_res in scan_report["details"]:
                filepath = file_res["filepath"]
                for secret in file_res.get("secrets", []):
                    table.add_row(
                        filepath,
                        secret["type"],
                        str(secret["line"]),
                        "[bold red]CRITICAL (Secret)[/bold red]",
                        f"Credential leaked: {secret['value']}"
                    )
                for vuln in file_res.get("vulnerabilities", []):
                    sev = vuln.get("severity", "LOW")
                    if sev == "HIGH":
                        sev_str = f"[bold red]{sev}[/bold red]"
                    elif sev == "MEDIUM":
                        sev_str = f"[bold yellow]{sev}[/bold yellow]"
                    else:
                        sev_str = f"[dim cyan]{sev}[/dim cyan]"
                    table.add_row(
                        filepath,
                        vuln["type"],
                        str(vuln["line"]),
                        sev_str,
                        vuln["description"]
                    )
            console.print(table)
        else:
            console.print("\n[success]✨ No security threats or vulnerabilities detected in this repository.[/success]\n")

    # Save output report JSON if requested
    if save_report:
        report_dir = os.path.join(root_dir, "data")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "security_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(scan_report, f, indent=2)
            f.write("\n")
        if display_results:
            console.print(f"[info]Saved security report to {report_path}[/info]")

    if display_results:
        status_color = "success" if scan_report["status"] == "PASSING" else "danger"
        status_emoji = "✅" if scan_report["status"] == "PASSING" else "❌"

        summary_text = (
            f"• Status: [{status_color}]{scan_report['status']}[/{status_color}] {status_emoji}\n"
            f"• Files Scanned: {scan_report['files_scanned']}\n"
            f"• Secrets Detected: [danger]{scan_report['secrets_found']}[/danger]\n"
            f"• Code Vulnerabilities: [warning]{scan_report['vulnerabilities_found']}[/warning]"
        )

        console.print(Panel(
            summary_text,
            title="[bold]Audit Summary[/bold]",
            border_style="cyan" if scan_report["status"] == "PASSING" else "red"
        ))

    return scan_report

def main():
    strict = "--strict" in sys.argv or "--fail-on-threats" in sys.argv
    quiet = "--quiet" in sys.argv
    output_json = "--json" in sys.argv

    scan_report = run_audit(
        root_dir=".",
        save_report=True,
        display_results=not (quiet or output_json)
    )

    if output_json:
        print(json.dumps(scan_report, indent=2))

    if scan_report["status"] == "FAILING":
        if not quiet:
            console.print("\n[danger]❌ Threat Detected! Please fix the reported items.[/danger]\n", file=sys.stderr)
        if strict:
            sys.exit(1)

if __name__ == "__main__":
    main()
