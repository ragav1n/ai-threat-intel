import requests
from urllib.parse import urljoin

# Base GitHub URLs to scan
GITHUB_SOURCES = [
    "https://github.com/ytisf/theZoo",
    "https://github.com/MISP/MISP",
    "https://github.com/mitre-attack/attack-stix-data",
    "https://github.com/redcanaryco/atomic-red-team",
    "https://github.com/csirtgadgets/massive-octo-nemesis"
]

def discover_github_atom_feeds():
    """
    For each GitHub repo, generate a list of Atom feed URLs:
    commits, issues, releases, etc.
    """
    feed_entries = []

    for repo_url in GITHUB_SOURCES:
        base_url = repo_url.rstrip("/")

        feed_entries.extend([
            {
                "name": f"{base_url.split('/')[-1]} Commits",
                "url": urljoin(base_url + "/", "commits/master.atom"),
                "category": "auto-discovered",
                "source_type": "github"
            },
            {
                "name": f"{base_url.split('/')[-1]} Issues",
                "url": urljoin(base_url + "/", "issues.atom"),
                "category": "auto-discovered",
                "source_type": "github"
            },
            {
                "name": f"{base_url.split('/')[-1]} Releases",
                "url": urljoin(base_url + "/", "releases.atom"),
                "category": "auto-discovered",
                "source_type": "github"
            }
        ])

    return feed_entries
