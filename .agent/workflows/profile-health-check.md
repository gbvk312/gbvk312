---
description: Perform a health check on the profile components (stats, metrics, links).
---

1.  **Check README.md URLs**:
    *   Find all `img` tags and links in the `README.md`.
    *   Use `read_url_content` to verify that they are accessible.
    *   Specifically check for `github-readme-stats` and `github-metrics` URLs.

2.  **Verify Stats Rendering**:
    *   Use `browser_subagent` to render the profile if any URL returns a 5xx or 4xx error.
    *   If `github-readme-stats.vercel.app` is failing, check if `github-readme-stats-anuraghazra1.vercel.app` is working.

3.  **Sync Metrics & Snake**:
    *   If the "Snake" image is broken, run `git fetch origin output:output --force` and verify `github-contribution-grid-snake.svg` exists.
    *   If the "Achievements" or "Metrics" images are broken, run `git fetch origin metrics:metrics --force` to sync the metrics branch.
    *   Verify if the files `github-achievements.svg` and `github-metrics.svg` exist on that branch.

4.  **Report**:
    *   Inform the user if any component needs manual intervention (e.g., refreshing a token).
