# Using N8N To Orchestrate Web and Mobile Bug Hunting

Modern bug hunting increasingly relies on automation, integration, and orchestration to scale reconnaissance and streamline reporting. This setup demonstrates how **n8n** serves as a centralized control plane to coordinate multiple tools and data flows across the bug hunting workflow. Through **AutoAR’s REST API**, it automates comprehensive web reconnaissance and attack surface mapping, while **Notion** acts as the central database for tracking targets and scan states. **Discord** provides real-time operational alerts, and **AI-assisted reporting** ensures consistent, high-quality documentation of findings.

Additionally, advanced mobile analysis is handled through **APKX**, an integrated Android/iOS pipeline connected to n8n. This enables intelligent caching, deep static and dynamic analysis, MITM patching, and automated report generation from app binaries obtained via store integrations.

Together, these components form a scalable, modular, and intelligent framework that enhances the efficiency and precision of modern bug bounty operations.

#### Architecture Overview

* n8n: event bus, scheduler, and workflow engine
* [AutoAR](https://github.com/h0tak88r/AutoAR): web recon/attack surface scans via REST API (subfinder, httpx, dnsx, naabu, nuclei, Dalfox, trufflehog, ffuf/fuzzuli, etc.)
* [APKX](https://github.com/h0tak88r/apkX) (Android/iOS): mobile application analysis pipelines, integrated via n8n — advanced APK/IPA analysis with intelligent caching, pattern matching, HTML/JSON reporting, MITM patching, app store downloads, and iOS ipatool integration (see [apkX repository](https://github.com/h0tak88r/apkX))
* Notion: single source of truth for targets and statuses
* Discord: real‑time notifications (capacity, completion, errors)
* AI reporting: OpenRouter model drafting structured markdown reports

<figure><img src="../.gitbook/assets/image (346).png" alt=""><figcaption></figcaption></figure>

#### Workflow In Practice

1. Intake in Notion

* New items are added to a Notion database with fields like Target and Scan Type.
* n8n watches Notion and triggers when a new/updated record needs a scan.

2. Capacity Guard

* n8n queries AutoAR `/capacity`. If at capacity, a Discord warning is posted and the item is deferred.

3. Launch Scan

* n8n POSTs to AutoAR `/scan` with the chosen scan type. AutoAR runs asynchronously and stores results under `new-results/`.

4. Persistence and Status

* Once completed, n8n sets the Notion item to “Completed”. Discord receives a concise completion message and, when useful, file artifacts (lists, findings, wordlists).

5. AI‑Assisted Reporting

* A dedicated n8n flow sends structured findings to an LLM via OpenRouter and writes a clean, templated markdown report back into Notion for review.

<figure><img src="../.gitbook/assets/image (347).png" alt=""><figcaption></figcaption></figure>

#### Scan Types (What I Run and Why)

**Domain**

* Full domain reconnaissance across subdomains, live host filtering, URL harvesting, technology detection, DNS checks, nuclei templates, reflection, JS exposure scans, port scanning, and vulnerability patterns.
* Best for comprehensive coverage on a root program domain.

**Subdomain**

* Targets a single subdomain with the same core modules (URLs, JS, reflection, tech detection, nuclei, ports, etc.).
* Useful for deep‑dive validation or triaging high‑value assets quickly.

**liteScan**

* Fast but broad: subdomain enumeration, CNAME checks, live hosts, technology detection, dangling DNS, reflection, URLs + JS exposure, nuclei scans, and optional backup exposure discovery.
* My default when I want actionable results quickly without the full weight of a domain‑wide run.

**fastLook**

* Minimal reconnaissance: subenum → live hosts → URLs → tech detect → CNAME check → reflection.
* Great for “is this worth a deeper look?”

**JSScan**

* JavaScript-focused analysis: collects JS files, analyzes for secrets, XSS vulnerabilities, and API endpoints.
* Perfect for modern web applications with heavy JS usage.

**JSMonitor**

* Monitors JavaScript files for changes and alerts on modifications.
* Useful for tracking dynamic applications and detecting new endpoints.

**BackupScan**

* Backup file discovery using fuzzuli on live subdomains.
* Finds configuration files, backups, and sensitive data exposure.

**S3Scan**

* S3 bucket permission testing (read, write, delete, public access).
* Critical for cloud storage security assessment.

**GitHub (Repo, Org, Wordlist)**

* **github\_single\_repo**: Scans a single repository for secrets with modern TruffleHog, producing JSON/HTML artifacts.
* **github\_org\_scan**: Scans an organization's public surface for secret leaks across repos.
* **github\_wordlist**: Generates a deduplicated wordlist from an organization's ignore files (e.g., `.gitignore`, `.npmignore`, `.dockerignore`).
  * Filters comments/empties/HTML, normalizes slashes, enforces safe charset/length, and sends to Discord.
  * Uses GitHub CLI when available; otherwise falls back to REST + raw.

**Monitoring**

* **Company Monitoring**: Monitors specific company targets for changes and new findings.
* **All Monitoring**: Comprehensive monitoring across all configured targets with automated re-scanning.

**Android (APKX pipeline)**

* Orchestrated via n8n to APKX mobile backend for Android.
* **Analysis Capabilities**: 1600+ security patterns, Manifest security review (exported components, task hijacking, deep links), insecure storage checks, cert pinning analysis, debug mode detection, Janus vulnerability detection.
* **Operational Features**: queueing, capacity checks, app download from multiple sources (APKPure, Google Play, F-Droid, Huawei AppGallery), optional MITM patching (`apk-mitm`) for HTTPS inspection, intelligent caching, HTML/JSON reporting.
* **Storage**: GitLab integration for zero-local storage mode with automatic sync.
* Tracked and closed out in Notion when processing ends.

**iOS (APKX iOS pipeline)**

* Orchestrated via n8n to APKX iOS backend, including capacity checks, job submission, and Discord reporting.
* **Analysis Capabilities**: IPA analysis, binary plist parsing, iOS security checks (ATS, jailbreak detection, keychain and file protection review), Swift/Objective-C analysis, bundle analysis.
* **Download**: ipatool-based downloads with Apple ID authentication.
* **Storage**: GitLab integration for cloud-based report storage.
* Managed as first‑class entries in the same Notion board.

#### Tooling Ecosystem (Key Integrations)

* Subdomain/host: subfinder, httpx, dnsx
* Ports: naabu
* Vuln templates: nuclei (public and custom)
* Web vulns: Dalfox (XSS), GF patterns (xss/sqli/etc.), reflection checks
* Content discovery: ffuf, fuzzuli (backup/config leakage)
* GitHub: trufflehog (repo/org), gh (org listing), raw fetching
* Mobile: APKX pipelines (Android/iOS) via n8n — see [apkX](https://github.com/h0tak88r/apkX)

#### Discord Integration

* **Real-time Notifications**: Capacity warnings, scan completion, errors, and status updates.
* **Artifact Sharing**: AutoAR sends wordlists, secret findings, and scan summaries as file attachments.
* **APKX Reports**: Mobile analysis results (HTML/JSON) posted to Discord channels with download links.
* **Webhook Configuration**: Per-scan webhook URLs for targeted notifications.
* **Rich Embeds**: Structured messages with scan metadata, findings counts, and direct links to reports.

<figure><img src="../.gitbook/assets/image (349).png" alt=""><figcaption></figcaption></figure>

### Screenshots

<figure><img src="../.gitbook/assets/image (350).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (351).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (352).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (353).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (354).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (355).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (356).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (357).png" alt=""><figcaption></figcaption></figure>

#### Why This Automation Works

* Consistency: Every run is defined, logged, and repeatable.
* Scale: Capacity checks prevent overload and degraded results.
* Speed: One click in Notion triggers end‑to‑end workflows.
* Signal over noise: Discord carries just the right events; detailed data lives in results and Notion.
* Extensibility: New tools are new nodes; new scans are new API routes.
* Quality: AI drafts structured reports so I spend time validating and expanding impact.

#### Operational Tips

* Keep tokens and webhooks in configuration, never in code.
* Let n8n gate execution on `/capacity` for stable throughput.
* Store canonical statuses in Notion; treat Discord as a broadcast channel.
* Restart the API when adding new scan types or capabilities.

#### Outcome

This setup turns recon and analysis into a controlled system: n8n orchestrates, AutoAR executes, Notion tracks, Discord informs, and AI accelerates reporting. It’s professional, maintainable, and easy to extend as programs evolve.
