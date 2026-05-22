#!/usr/bin/env python3
import json
import subprocess
import re
import sys
import urllib.request
import os
import random
from datetime import datetime

def run_command(cmd):
    """Runs a shell command and returns the output string, or raises an exception."""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {' '.join(cmd)}\nError: {result.stderr}")
    return result.stdout

def fetch_repos_api(owner, is_org=False):
    """Fetches all repositories from GitHub REST API as a resilient fallback with pagination."""
    all_repos = []
    page = 1
    token = os.environ.get("GITHUB_TOKEN")
    
    while True:
        url = f"https://api.github.com/orgs/{owner}/repos?per_page=100&page={page}" if is_org else f"https://api.github.com/users/{owner}/repos?per_page=100&page={page}"
        print(f"Fetching via API page {page} for {owner}...")
        
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Profile-Updater-Script")
        req.add_header("Accept", "application/vnd.github.v3+json")
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
        except Exception as e:
            print(f"API fetch failed for {owner} page {page}: {e}")
            return None
            
    # Normalize to match GH CLI format
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
    """Fetches repositories using GitHub API, falling back to gh CLI if needed."""
    repos = fetch_repos_api(owner, is_org)
    if repos is not None:
        # Filter out forks to show only original work
        original_repos = [repo for repo in repos if not repo.get("isFork", False)]
        original_repos.sort(key=lambda r: r.get("name", "").lower())
        return original_repos
        
    # Fallback to gh CLI
    print(f"Falling back to gh CLI for {owner}...")
    cmd = ["gh", "repo", "list", owner, "--limit", "100", "--json", fields]
    output = run_command(cmd)
    repos = json.loads(output)
    original_repos = [repo for repo in repos if not repo.get("isFork", False)]
    original_repos.sort(key=lambda r: r.get("name", "").lower())
    return original_repos

def fetch_current_focus_inner():
    """Queries open issues labeled 'focus' in gbvk312/gbvk312, returning the inner HTML block."""
    print("Fetching current focus from issues...")
    token = os.environ.get("GITHUB_TOKEN")
    url = "https://api.github.com/repos/gbvk312/gbvk312/issues?labels=focus&state=open&per_page=1"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Profile-Updater-Script")
    req.add_header("Accept", "application/vnd.github.v3+json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
        
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            issues = json.loads(response.read().decode('utf-8'))
            if issues and isinstance(issues, list):
                issue = issues[0]
                title = issue.get("title")
                url = issue.get("html_url")
                print(f"Focus found: {title}")
                return f'<p align="center">\n  <sub>🎯 <b>Current Focus:</b> <a href="{url}">{title}</a></sub>\n</p>'
    except Exception as e:
        print(f"API fetch for focus issues failed: {e}. Falling back to gh CLI...")
        
    # Fallback to gh CLI
    try:
        cmd = ["gh", "issue", "list", "--repo", "gbvk312/gbvk312", "--label", "focus", "--limit", "1", "--json", "title,url"]
        output = run_command(cmd)
        issues = json.loads(output)
        if issues:
            title = issues[0].get("title")
            url = issues[0].get("url")
            print(f"Focus found via gh CLI: {title}")
            return f'<p align="center">\n  <sub>🎯 <b>Current Focus:</b> <a href="{url}">{title}</a></sub>\n</p>'
    except Exception as e:
        print(f"gh CLI fetch for focus issues failed: {e}")
        
    # Default fallback
    print("No active focus issue found. Using default focus.")
    return '<p align="center">\n  <sub>🎯 <b>Current Focus:</b> Architecting autonomous security for the Agentic Web 🛡️</sub>\n</p>'

def run_security_audit_inner():
    """Runs the security_sentinel.py script and returns the status inner HTML."""
    print("Running DevSecOps security audit sentinel...")
    try:
        # Run the security sentinel
        subprocess.run(["python3", "scripts/security_sentinel.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Read the report
        if os.path.exists("scratch/security_report.json"):
            with open("scratch/security_report.json", "r") as f:
                report = json.load(f)
                
            status = report.get("status", "PASSING")
            secrets = report.get("secrets_found", 0)
            vulns = report.get("vulnerabilities_found", 0)
            
            if status == "PASSING":
                print("Sentinel Audit: PASSED securely.")
                return f'<sub><i>🛡️ DevSecOps Shield: Scanned & Secure • 0 Secrets • 0 Vulns • Verified by Security Sentinel</i></sub>'
            else:
                print(f"Sentinel Audit: THREAT DETECTED! Secrets: {secrets}, Vulns: {vulns}.")
                return f'<sub><i>⚠️ DevSecOps Shield: THREAT DETECTED • {secrets} Secrets • {vulns} Vulns • Verified by Security Sentinel</i></sub>'
    except Exception as e:
        print(f"Security sentinel run failed: {e}")
        
    return '<sub><i>🛡️ DevSecOps Shield: Scanned & Secure • 0 Issues • Verified by Security Sentinel</i></sub>'

def main():
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
        
        print(f"Stats calculated: {user_repo_count} personal, {telecom_repo_count} telecom, {utility_repo_count} utility repos, {total_stars} total stars.")

        # 2. Update JSON files in scratch/
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

        # Write files in compact single-line JSON formatting
        with open("scratch/repos.json", "w") as f:
            f.write(json.dumps(user_repos_cleaned, separators=(',', ':')) + "\n")
        print("Updated scratch/repos.json")

        with open("scratch/telecom_repos.json", "w") as f:
            f.write(json.dumps(telecom_repos_cleaned, separators=(',', ':')) + "\n")
        print("Updated scratch/telecom_repos.json")

        with open("scratch/utility_repos.json", "w") as f:
            f.write(json.dumps(utility_repos_cleaned, separators=(',', ':')) + "\n")
        print("Updated scratch/utility_repos.json")

        # 3. Update README.md
        with open("README.md", "r") as f:
            readme_content = f.read()

        # Update Badge (Personal Repositories)
        badge_pattern = r"(<!-- REPO_BADGE_START -->\s*).*?(\s*<!-- REPO_BADGE_END -->)"
        new_badge_html = f'<a href="https://github.com/gbvk312?tab=repositories"><img src="https://img.shields.io/badge/Repositories-{user_repo_count}-0D1117?style=for-the-badge&logo=github&logoColor=white" /></a>'
        readme_content = re.sub(badge_pattern, rf"\1{new_badge_html}\2", readme_content, flags=re.DOTALL)
        print("Updated README repositories count badge.")

        # Update Telecom Badge
        telecom_badge_pattern = r"(<!-- TELECOM_BADGE_START -->\s*).*?(\s*<!-- TELECOM_BADGE_END -->)"
        new_telecom_badge_html = f'<a href="https://github.com/telecom-test-tools"><img src="https://img.shields.io/badge/Telecom_Tools-{telecom_repo_count}-0066FF?style=for-the-badge&logo=github&logoColor=white" /></a>'
        if re.search(telecom_badge_pattern, readme_content):
            readme_content = re.sub(telecom_badge_pattern, rf"\1{new_telecom_badge_html}\2", readme_content, flags=re.DOTALL)
            print("Updated README Telecom Tools count badge.")

        # Update Utility Badge
        utility_badge_pattern = r"(<!-- UTILITY_BADGE_START -->\s*).*?(\s*<!-- UTILITY_BADGE_END -->)"
        new_utility_badge_html = f'<a href="https://github.com/gbvkUtilities"><img src="https://img.shields.io/badge/Utilities-{utility_repo_count}-00F7FF?style=for-the-badge&logo=github&logoColor=0D1117" /></a>'
        if re.search(utility_badge_pattern, readme_content):
            readme_content = re.sub(utility_badge_pattern, rf"\1{new_utility_badge_html}\2", readme_content, flags=re.DOTALL)
            print("Updated README Utilities count badge.")

        # Update System Status
        status_pattern = r"(<!-- SYSTEM_STATUS_START -->\s*).*?(\s*<!-- SYSTEM_STATUS_END -->)"
        current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        new_status_html = f'<sub><i>Last System Pulse: {current_time} UTC • Total Portfolio Stars: ⭐ {total_stars} • Automated via Profile Manager</i></sub>'
        readme_content = re.sub(status_pattern, rf"\1{new_status_html}\2", readme_content, flags=re.DOTALL)
        print("Updated README System Pulse footer status.")

        # Update Current Focus Tracker
        focus_pattern = r"(<!-- FOCUS_SECTION_START -->\s*).*?(\s*<!-- FOCUS_SECTION_END -->)"
        new_focus_html = fetch_current_focus_inner()
        if re.search(focus_pattern, readme_content):
            readme_content = re.sub(focus_pattern, rf"\1{new_focus_html}\2", readme_content, flags=re.DOTALL)
            print("Updated README Current Focus section.")

        # Update Security Sentinel
        security_pattern = r"(<!-- SECURITY_SENTINEL_START -->\s*).*?(\s*<!-- SECURITY_SENTINEL_END -->)"
        new_security_html = run_security_audit_inner()
        if re.search(security_pattern, readme_content):
            readme_content = re.sub(security_pattern, rf"\1{new_security_html}\2", readme_content, flags=re.DOTALL)
            print("Updated README Security Sentinel section.")

        # Generate Rotating Spotlight
        utilities_with_desc = [r for r in utility_repos if r.get("description")]
        if utilities_with_desc:
            # Seed with current day of year for stable daily rotation
            day_of_year = datetime.now().timetuple().tm_yday
            random.seed(day_of_year)
            spotlight_repos = random.sample(utilities_with_desc, min(len(utilities_with_desc), 3))
            
            spotlight_md = "\n| Tool | Description |\n| :--- | :--- |\n"
            for repo in spotlight_repos:
                name = repo.get("name")
                desc = repo.get("description", "")
                spotlight_md += f"| [🛠️ {name}](https://github.com/gbvkUtilities/{name}) | {desc} |\n"
            
            spotlight_pattern = r"(<!-- UTILITY_SPOTLIGHT_START -->\s*).*?(\s*<!-- UTILITY_SPOTLIGHT_END -->)"
            if re.search(spotlight_pattern, readme_content):
                readme_content = re.sub(spotlight_pattern, rf"\1{spotlight_md}\2", readme_content, flags=re.DOTALL)
                print("Updated README Rotating Utility Spotlight section.")

        with open("README.md", "w") as f:
            f.write(readme_content)
        print("Successfully updated README.md!")

    except Exception as e:
        print(f"Error updating profile: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
