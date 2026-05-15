# IOC Verification — Analyst Instructions

Thanks for adjudicating this sample. It validates the machine-generated IOC
labels for a research dataset. Two automated systems labelled IOCs in 134
threat reports; they disagree, and we need a human ground-truth call.

## The task

Open `verification_sample.csv`. It has **150 rows**, one per indicator. For
each row, fill the **`is_true_ioc`** column with `yes`, `no`, or `unsure`,
based on the `context` snippet (the report text around the indicator).

Please **ignore the `label_source` column** while judging — it records which
system found the indicator and could bias you. Judge each string on its merits.
`notes` is optional but useful for borderline calls.

## The core question

> **If a defender found this exact string in their own network or logs, would
> it indicate a compromise?**

Equivalently: did the *attacker* create, control, or maliciously use this
artifact — or is it just *mentioned* in the report?

## `yes` — a genuine IOC

- Attacker infrastructure: C2 servers, phishing/malware domains, payload URLs,
  attacker-controlled IPs
- Malware identity: file hashes (MD5/SHA1/SHA256) of malicious samples,
  malicious filenames
- Attacker email addresses (phishing sender, ransom contact)

## `no` — not an IOC (IOC-shaped, but benign)

- The **report publisher's own** website or blog URL (appears in headers/footers)
- **Reference / citation links** — other articles, news, advisories,
  `cisa.gov/privacy-policy`-type pages, MITRE pages
- Documentation, official product pages, vendor security guidelines
- Legitimate services as context (`github.com`, `google.com`, `microsoft.com`)
  — **unless** the report explicitly says the attacker abused that exact resource
- The victim organisation's own legitimate domain
- Placeholder / example values (`malicious-website.com`, `example.com`, `1.2.3.4`)

## `unsure` — genuine ambiguity (do not guess)

- A legitimate service the attacker abused (e.g. an `ngrok-free.app` tunnel, a
  `pastebin` link). Rule of thumb: the *specific* attacker URL/subdomain is an
  IOC (`yes`); the bare service domain alone is not (`no`). If unclear, `unsure`.
- **CVEs** — a CVE identifies a vulnerability, not a hunt-able artifact, so most
  analysts treat a CVE as **not** an IOC. Please apply one convention to *every*
  CVE consistently (we suggest `no`).
- The snippet is too thin to judge.

## If you need more context

The full report text is in `new_real_world_dataset.json` in this folder, keyed
by the `sample_id` column.

When done, return the filled CSV — agreement scoring is automated from it.
