#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "rich",
# ]
# ///
import json
import subprocess
import re
import sys
import html
import urllib.request
import urllib.error
import os
import random
from datetime import datetime, timezone

# Ensure local script directory is in sys.path for direct module imports
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Graceful fallback for Rich to ensure zero-dependency portability
try:
    from rich.console import Console
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

    class Console:
        def __init__(self, theme=None):
            self.theme = theme

        def print(self, *args, **kwargs):
            file = kwargs.get("file", sys.stdout)
            clean_args = []
            for arg in args:
                if isinstance(arg, Panel):
                    clean_args.append(str(arg))
                else:
                    clean_text = re.sub(r'\[/?[a-zA-Z0-9_\- ]+\]', '', str(arg))
                    clean_args.append(clean_text)
            print(*clean_args, file=file)

    console = Console()

def run_command(cmd):
    """Runs a shell command and returns the output string, or raises an exception."""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {' '.join(cmd)}\nError: {result.stderr.strip()}")
    return result.stdout

def fetch_repos_api(owner, is_org=False):
    """Fetches all repositories from GitHub REST API as a resilient fallback with pagination."""
    all_repos = []
    page = 1
    token = os.environ.get("GITHUB_TOKEN")

    while True:
        url = (
            f"https://api.github.com/orgs/{owner}/repos?per_page=100&page={page}"
            if is_org
            else f"https://api.github.com/users/{owner}/repos?per_page=100&page={page}"
        )
        console.print(f"[info]Fetching API page {page} for {owner}...[/info]")

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Profile-Updater-Script")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                if not data:
                    break
                all_repos.extend(data)
                if len(data) < 100:
                    break
                page += 1
        except urllib.error.HTTPError as e:
            console.print(f"[warning]GitHub API HTTP {e.code} for {owner} page {page}: {e.reason}[/warning]")
            return None
        except Exception as e:
            console.print(f"[warning]API fetch failed for {owner} page {page}: {e}[/warning]")
            return None

    # Normalize to standard repository format
    normalized = []
    for r in all_repos:
        is_fork = r.get("fork", False)
        topics = [{"name": t} for t in r.get("topics", [])]

        normalized.append({
            "name": r.get("name"),
            "description": r.get("description") or "",
            "stargazerCount": r.get("stargazers_count", 0),
            "pushedAt": r.get("pushed_at"),
            "repositoryTopics": topics,
            "isFork": is_fork
        })
    return normalized

def fetch_repos(owner, fields, is_org=False):
    """
    Fetches repositories using GitHub API, falling back to gh CLI,
    and finally to local data/*.json cache for offline resilience.
    """
    repos = fetch_repos_api(owner, is_org)
    if repos is not None:
        original_repos = [repo for repo in repos if not repo.get("isFork", False)]
        original_repos.sort(key=lambda r: r.get("name", "").lower())
        return original_repos

    # Fallback 1: gh CLI
    console.print(f"[warning]Falling back to gh CLI for {owner}...[/warning]")
    try:
        cmd = ["gh", "repo", "list", owner, "--limit", "100", "--json", fields]
        output = run_command(cmd)
        repos = json.loads(output)
        original_repos = [repo for repo in repos if not repo.get("isFork", False)]
        original_repos.sort(key=lambda r: r.get("name", "").lower())
        return original_repos
    except Exception as e:
        console.print(f"[warning]gh CLI fetch failed for {owner}: {e}[/warning]")

    # Fallback 2: Cached data files in data/
    cache_map = {
        "gbvk312": "data/repos.json",
        "telecom-test-tools": "data/telecom_repos.json",
        "gbvkUtilities": "data/utility_repos.json"
    }
    cache_file = cache_map.get(owner)
    if cache_file and os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
            console.print(f"[warning]Loaded {len(cached_data)} cached repositories for {owner} from {cache_file}[/warning]")
            return cached_data
        except Exception as e:
            console.print(f"[danger]Failed to load cache file {cache_file}: {e}[/danger]")

    return []

def fetch_current_focus_inner():
    """Queries open issues labeled 'focus' in gbvk312/gbvk312, returning the inner HTML block."""
    console.print("[info]Fetching current focus from issues...[/info]")
    token = os.environ.get("GITHUB_TOKEN")
    url = "https://api.github.com/repos/gbvk312/gbvk312/issues?labels=focus&state=open&per_page=1"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Profile-Updater-Script")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            issues = json.loads(response.read().decode('utf-8'))
            if issues and isinstance(issues, list):
                issue = issues[0]
                title = html.escape(issue.get("title", ""))
                issue_url = issue.get("html_url", "")
                console.print(f"[info]Focus found: {title}[/info]")
                return f'<p align="center">\n  <sub>🎯 <b>Current Focus:</b> <a href="{issue_url}">{title}</a></sub>\n</p>'
    except Exception as e:
        console.print(f"[warning]API fetch for focus issues failed: {e}. Falling back to gh CLI...[/warning]")

    # Fallback to gh CLI
    try:
        cmd = ["gh", "issue", "list", "--repo", "gbvk312/gbvk312", "--label", "focus", "--limit", "1", "--json", "title,url"]
        output = run_command(cmd)
        issues = json.loads(output)
        if issues:
            title = html.escape(issues[0].get("title", ""))
            issue_url = issues[0].get("url", "")
            console.print(f"[info]Focus found via gh CLI: {title}[/info]")
            return f'<p align="center">\n  <sub>🎯 <b>Current Focus:</b> <a href="{issue_url}">{title}</a></sub>\n</p>'
    except Exception as e:
        console.print(f"[warning]gh CLI fetch for focus issues failed: {e}[/warning]")

    # Default fallback
    console.print("[info]No active focus issue found. Using default focus.[/info]")
    return '<p align="center">\n  <sub>🎯 <b>Current Focus:</b> <a href="https://github.com/gbvk312/multi-agent-orchestrator">Hardening the asynchronous multi-agent orchestrator framework</a></sub>\n</p>'

def run_security_audit_inner():
    """Runs the DevSecOps security audit sentinel and returns the status inner HTML."""
    console.print("[info]Running DevSecOps security audit sentinel...[/info]")
    try:
        # Try direct in-process audit invocation
        try:
            import security_sentinel
            report = security_sentinel.run_audit(root_dir=".", save_report=True, display_results=True)
        except Exception:
            # Subprocess fallback
            sentinel_script = os.path.join(script_dir, "security_sentinel.py")
            subprocess.run([sys.executable, sentinel_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if os.path.exists("data/security_report.json"):
                with open("data/security_report.json", "r", encoding="utf-8") as f:
                    report = json.load(f)
            else:
                raise RuntimeError("Security report was not generated.")

        status = report.get("status", "PASSING")
        secrets = report.get("secrets_found", 0)
        vulns = report.get("vulnerabilities_found", 0)

        if status == "PASSING":
            console.print("[success]Sentinel Audit: PASSED securely.[/success]")
            return '<sub><i>🛡️ DevSecOps Shield: Scanned & Secure • 0 Secrets • 0 Vulns • Verified by Security Sentinel</i></sub>'
        else:
            console.print(f"[danger]Sentinel Audit: THREAT DETECTED! Secrets: {secrets}, Vulns: {vulns}.[/danger]")
            return f'<sub><i>⚠️ DevSecOps Shield: THREAT DETECTED • {secrets} Secrets • {vulns} Vulns • Verified by Security Sentinel</i></sub>'
    except Exception as e:
        console.print(f"[danger]Security sentinel run failed: {e}[/danger]")
        return '<sub><i>🛡️ DevSecOps Shield: Sentinel Audit Failed • Verified by Security Sentinel</i></sub>'

def safe_replace(pattern, repl_str, content):
    """Safely replaces regex matched regions using lambda to prevent backreference bugs."""
    if re.search(pattern, content):
        return re.sub(pattern, lambda m: f"{m.group(1)}{repl_str}{m.group(2)}", content, flags=re.DOTALL)
    return content

def main():
    console.print(Panel(
        "[bold cyan]🔄 Profile Manager Pulse[/bold cyan]\n[dim]Updating dynamic README elements & metrics...[/dim]",
        border_style="cyan"
    ))

    try:
        # 1. Fetch repositories
        user_repos = fetch_repos("gbvk312", "name,description,stargazerCount,pushedAt,repositoryTopics,isFork", is_org=False)
        telecom_repos = fetch_repos("telecom-test-tools", "name,description,stargazerCount,isFork", is_org=True)
        utility_repos = fetch_repos("gbvkUtilities", "name,description,stargazerCount,isFork", is_org=True)

        # Calculate stats
        user_repo_count = len(user_repos)
        telecom_repo_count = len(telecom_repos)
        utility_repo_count = len(utility_repos)

        # Calculate total stars across user and organization repos
        total_stars = (
            sum(r.get("stargazerCount", 0) for r in user_repos) +
            sum(r.get("stargazerCount", 0) for r in telecom_repos) +
            sum(r.get("stargazerCount", 0) for r in utility_repos)
        )

        console.print(
            f"[info]Stats: {user_repo_count} personal, {telecom_repo_count} telecom, {utility_repo_count} utility repos | {total_stars} total stars.[/info]"
        )

        # 2. Update JSON files in data/
        user_repos_cleaned = []
        for r in user_repos:
            user_repos_cleaned.append({
                "description": r.get("description") or "",
                "name": r.get("name"),
                "pushedAt": r.get("pushedAt"),
                "repositoryTopics": r.get("repositoryTopics") or [],
                "stargazerCount": r.get("stargazerCount", 0)
            })

        telecom_repos_cleaned = []
        for r in telecom_repos:
            telecom_repos_cleaned.append({
                "description": r.get("description") or "",
                "name": r.get("name"),
                "stargazerCount": r.get("stargazerCount", 0)
            })

        utility_repos_cleaned = []
        for r in utility_repos:
            utility_repos_cleaned.append({
                "description": r.get("description") or "",
                "name": r.get("name"),
                "stargazerCount": r.get("stargazerCount", 0)
            })

        # Write files in compact formatting
        os.makedirs("data", exist_ok=True)
        with open("data/repos.json", "w", encoding="utf-8") as f:
            f.write(json.dumps(user_repos_cleaned, separators=(',', ':')) + "\n")
        console.print("[success]Updated data/repos.json[/success]")

        with open("data/telecom_repos.json", "w", encoding="utf-8") as f:
            f.write(json.dumps(telecom_repos_cleaned, separators=(',', ':')) + "\n")
        console.print("[success]Updated data/telecom_repos.json[/success]")

        with open("data/utility_repos.json", "w", encoding="utf-8") as f:
            f.write(json.dumps(utility_repos_cleaned, separators=(',', ':')) + "\n")
        console.print("[success]Updated data/utility_repos.json[/success]")

        # 3. Update README.md
        with open("README.md", "r", encoding="utf-8") as f:
            readme_content = f.read()

        # Update Badge (Personal Repositories)
        badge_pattern = r"(<!-- REPO_BADGE_START -->\s*).*?(\s*<!-- REPO_BADGE_END -->)"
        new_badge_html = f'<a href="https://github.com/gbvk312?tab=repositories"><img src="https://img.shields.io/badge/Repositories-{user_repo_count}-0D1117?style=for-the-badge&logo=github&logoColor=white" /></a>'
        readme_content = safe_replace(badge_pattern, new_badge_html, readme_content)
        console.print("[success]Updated README repositories count badge.[/success]")

        # Update Telecom Badge
        telecom_badge_pattern = r"(<!-- TELECOM_BADGE_START -->\s*).*?(\s*<!-- TELECOM_BADGE_END -->)"
        new_telecom_badge_html = f'<a href="https://github.com/telecom-test-tools"><img src="https://img.shields.io/badge/Telecom_Tools-{telecom_repo_count}-0066FF?style=for-the-badge&logo=github&logoColor=white" /></a>'
        readme_content = safe_replace(telecom_badge_pattern, new_telecom_badge_html, readme_content)
        console.print("[success]Updated README Telecom Tools count badge.[/success]")

        # Update Utility Badge
        utility_badge_pattern = r"(<!-- UTILITY_BADGE_START -->\s*).*?(\s*<!-- UTILITY_BADGE_END -->)"
        new_utility_badge_html = f'<a href="https://github.com/gbvkUtilities"><img src="https://img.shields.io/badge/Utilities-{utility_repo_count}-00F7FF?style=for-the-badge&logo=github&logoColor=0D1117" /></a>'
        readme_content = safe_replace(utility_badge_pattern, new_utility_badge_html, readme_content)
        console.print("[success]Updated README Utilities count badge.[/success]")

        # Update System Status
        status_pattern = r"(<!-- SYSTEM_STATUS_START -->\s*).*?(\s*<!-- SYSTEM_STATUS_END -->)"
        current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        new_status_html = f'<sub><i>Last System Pulse: {current_time} UTC • Total Portfolio Stars: ⭐ {total_stars} • Automated via Profile Manager</i></sub>'
        readme_content = safe_replace(status_pattern, new_status_html, readme_content)
        console.print("[success]Updated README System Pulse footer status.[/success]")

        # Update Current Focus Tracker
        focus_pattern = r"(<!-- FOCUS_SECTION_START -->\s*).*?(\s*<!-- FOCUS_SECTION_END -->)"
        new_focus_html = fetch_current_focus_inner()
        readme_content = safe_replace(focus_pattern, new_focus_html, readme_content)
        console.print("[success]Updated README Current Focus section.[/success]")

        # Update Security Sentinel
        security_pattern = r"(<!-- SECURITY_SENTINEL_START -->\s*).*?(\s*<!-- SECURITY_SENTINEL_END -->)"
        new_security_html = run_security_audit_inner()
        readme_content = safe_replace(security_pattern, new_security_html, readme_content)
        console.print("[success]Updated README Security Sentinel section.[/success]")

        # Generate Rotating Spotlight
        utilities_with_desc = [r for r in utility_repos if r.get("description")]
        if utilities_with_desc:
            # Seed with current day of year for stable daily rotation (UTC)
            day_of_year = datetime.now(timezone.utc).timetuple().tm_yday
            random.seed(day_of_year)
            spotlight_repos = random.sample(utilities_with_desc, min(len(utilities_with_desc), 3))

            spotlight_md = "\n| Tool | Description |\n| :--- | :--- |\n"
            for repo in spotlight_repos:
                name = repo.get("name", "").strip()
                desc = repo.get("description", "").replace("|", "\\|").replace("\n", " ").strip()
                spotlight_md += f"| [🛠️ {name}](https://github.com/gbvkUtilities/{name}) | {desc} |\n"

            spotlight_pattern = r"(<!-- UTILITY_SPOTLIGHT_START -->\s*).*?(\s*<!-- UTILITY_SPOTLIGHT_END -->)"
            readme_content = safe_replace(spotlight_pattern, spotlight_md, readme_content)
            console.print("[success]Updated README Rotating Utility Spotlight section.[/success]")

        with open("README.md", "w", encoding="utf-8") as f:
            f.write(readme_content)
        console.print("[success]Successfully updated README.md![/success]")

    except Exception as e:
        console.print(f"[danger]Error updating profile: {e}[/danger]", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
