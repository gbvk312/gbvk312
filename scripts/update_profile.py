#!/usr/bin/env python3
import json
import subprocess
import re
import sys
from datetime import datetime

def run_command(cmd):
    """Runs a shell command and returns the output string, or raises an exception."""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {' '.join(cmd)}\nError: {result.stderr}")
    return result.stdout

def fetch_repos(owner, fields):
    """Fetches repositories for a user or organization using the gh CLI."""
    print(f"Fetching repositories for {owner}...")
    cmd = ["gh", "repo", "list", owner, "--limit", "100", "--json", fields]
    output = run_command(cmd)
    repos = json.loads(output)
    # Filter out forks to show only original work
    original_repos = [repo for repo in repos if not repo.get("isFork", False)]
    # Sort repositories by push time or name
    original_repos.sort(key=lambda r: r.get("name", "").lower())
    return original_repos

def main():
    try:
        # 1. Fetch repositories using gh CLI
        user_repos = fetch_repos("gbvk312", "name,description,stargazerCount,pushedAt,repositoryTopics,isFork")
        telecom_repos = fetch_repos("telecom-test-tools", "name,description,stargazerCount,isFork")
        utility_repos = fetch_repos("gbvkUtilities", "name,description,stargazerCount,isFork")
        
        # Calculate stats
        user_repo_count = len(user_repos)
        
        # Calculate total stars across user and organization repos
        total_stars = (
            sum(r.get("stargazerCount", 0) for r in user_repos) +
            sum(r.get("stargazerCount", 0) for r in telecom_repos) +
            sum(r.get("stargazerCount", 0) for r in utility_repos)
        )
        
        print(f"Stats calculated: {user_repo_count} personal repos, {total_stars} total stars.")

        # 2. Update JSON files in scratch/
        # Format user repos to keep fields we want
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

        # Write files in compact single-line JSON formatting to match original format
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

        # Update Badge
        badge_pattern = r"(<!-- REPO_BADGE_START -->\s*).*?(\s*<!-- REPO_BADGE_END -->)"
        new_badge_html = f'<a href="https://github.com/gbvk312?tab=repositories"><img src="https://img.shields.io/badge/Repositories-{user_repo_count}-0D1117?style=for-the-badge&logo=github&logoColor=white" /></a>'
        readme_content = re.sub(badge_pattern, rf"\1{new_badge_html}\2", readme_content, flags=re.DOTALL)
        print("Updated README repositories count badge.")

        # Update System Status
        status_pattern = r"(<!-- SYSTEM_STATUS_START -->\s*).*?(\s*<!-- SYSTEM_STATUS_END -->)"
        current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        new_status_html = f'<sub><i>Last System Pulse: {current_time} UTC • Total Portfolio Stars: ⭐ {total_stars} • Automated via Profile Manager</i></sub>'
        readme_content = re.sub(status_pattern, rf"\1{new_status_html}\2", readme_content, flags=re.DOTALL)
        print("Updated README System Pulse footer status.")

        with open("README.md", "w") as f:
            f.write(readme_content)
        print("Successfully updated README.md!")

    except Exception as e:
        print(f"Error updating profile: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
