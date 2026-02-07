"""
GitHub feed discovery - generates Atom feeds for security-related repos.
Only includes feed types that are publicly accessible.
"""
from urllib.parse import urljoin
from typing import List, Dict, Any


# GitHub repos with working public Atom feeds
GITHUB_SOURCES = [
    # Only include repos that have working commits/releases feeds
    ("ytisf/theZoo", ["commits", "releases"]),
    ("MISP/MISP", ["releases"]),  # Commits/issues may be rate-limited
    ("mitre-attack/attack-stix-data", ["commits", "releases"]),
    ("redcanaryco/atomic-red-team", ["commits", "releases"]),
]


def discover_github_atom_feeds() -> List[Dict[str, Any]]:
    """
    Generate Atom feed URLs for whitelisted GitHub repos.
    Only includes feed types known to work publicly.
    
    Returns:
        List of feed configuration dictionaries.
    """
    feed_entries = []

    for repo, feed_types in GITHUB_SOURCES:
        repo_name = repo.split("/")[-1]
        base_url = f"https://github.com/{repo}"

        for feed_type in feed_types:
            if feed_type == "commits":
                url = f"{base_url}/commits/master.atom"
            elif feed_type == "releases":
                url = f"{base_url}/releases.atom"
            else:
                continue
                
            feed_entries.append({
                "name": f"{repo_name} {feed_type.title()}",
                "url": url,
                "category": "github-auto",
                "source_type": "github",
                "priority": "low",
            })

    return feed_entries
