# Using N8N To Orchestrate Web and Mobile Bug Hunting

Understood. Here is your write-up fully **edited and optimized for publication** — polished, structured, and professional, while keeping your technical depth intact and maintaining your tone.

***

## **Using n8n to Orchestrate Web and Mobile Bug Hunting**

#### **Introduction**

Modern bug hunting increasingly relies on **automation**, **integration**, and **orchestration** to scale reconnaissance and streamline reporting. Manual workflows struggle to keep pace with the complexity and speed of modern attack surfaces.

This setup demonstrates how **n8n** serves as a **centralized control plane** to coordinate multiple tools and data flows across the bug-hunting lifecycle. Through **AutoAR’s REST API**, it automates comprehensive web reconnaissance and attack surface mapping, while **Notion** provides a single source of truth for tracking targets and scan states. **Discord** delivers real-time operational alerts, and **AI-assisted reporting** ensures consistent, high-quality documentation of findings.

Advanced mobile analysis is handled through **APKX**, an integrated Android/iOS pipeline connected to n8n. This enables intelligent caching, deep static and dynamic analysis, MITM patching, and automated report generation from app binaries acquired via store integrations.

Together, these components form a **scalable, modular, and intelligent framework** that enhances the efficiency and precision of modern bug bounty operations.

***

### **Architecture Overview**

| Component              | Purpose                                                                                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **n8n**                | Event bus, scheduler, and workflow engine                                                                                                              |
| **AutoAR**             | Web reconnaissance and attack surface scanning via REST API (subfinder, httpx, dnsx, naabu, nuclei, Dalfox, trufflehog, ffuf/fuzzuli, etc.)            |
| **APKX (Android/iOS)** | Mobile analysis pipeline integrated via n8n — advanced APK/IPA analysis, intelligent caching, pattern matching, MITM patching, and HTML/JSON reporting |
| **Notion**             | Source of truth for targets and scan statuses                                                                                                          |
| **Discord**            | Real-time notifications (capacity, completion, errors)                                                                                                 |
| **AI Reporting**       | Uses OpenRouter models to generate structured Markdown reports                                                                                         |

***

### **Workflow in Practice**

#### **1. Intake in Notion**

* Targets and scan types are defined in a Notion database.
* n8n monitors for new or updated entries and triggers workflows automatically.

#### **2. Capacity Guard**

* n8n queries `AutoAR /capacity`.
* If the system is at capacity, n8n posts a **Discord warning** and defers the task to maintain stability.

#### **3. Launch Scan**

* n8n submits a `POST /scan` request to AutoAR with the chosen scan type.
* AutoAR executes asynchronously and stores results under `new-results/`.

#### **4. Persistence and Status**

* When the scan completes, n8n marks the Notion item as **Completed**.
* Discord receives a concise notification with any relevant artifacts (lists, findings, wordlists).

#### **5. AI-Assisted Reporting**

* Structured findings are sent to an LLM via **OpenRouter**.
* The model drafts a clean Markdown report, which is written back to Notion for analyst review and validation.

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

### **Scan Types**

<table><thead><tr><th width="184">Type</th><th width="343">Description</th><th>Best Use</th></tr></thead><tbody><tr><td><strong>Domain</strong></td><td>Full reconnaissance: subdomains, live hosts, URLs, tech stack, DNS checks, nuclei templates, reflection, JS exposure, ports, and vulnerabilities</td><td>Comprehensive program coverage</td></tr><tr><td><strong>Subdomain</strong></td><td>Focused scan on one subdomain with same modules as Domain</td><td>Deep-dive triage of high-value assets</td></tr><tr><td><strong>liteScan</strong></td><td>Fast subdomain enumeration, live hosts, tech detection, reflection, and nuclei checks</td><td>Quick actionable overview</td></tr><tr><td><strong>fastLook</strong></td><td>Minimal recon: subenum → live hosts → URLs → tech detect → reflection</td><td>Rapid prioritization</td></tr><tr><td><strong>JSScan</strong></td><td>JavaScript collection and analysis for secrets, XSS, and API endpoints</td><td>JS-heavy applications</td></tr><tr><td><strong>JSMonitor</strong></td><td>Monitors JS files for modifications</td><td>Detecting new endpoints or changes or secrets</td></tr><tr><td><strong>BackupScan</strong></td><td>Fuzzes for exposed backups/config files</td><td>Backup Files Exposure</td></tr><tr><td><strong>S3Scan</strong></td><td>Tests S3 bucket permissions</td><td>Cloud exposure assessment</td></tr><tr><td><strong>GitHub (Repo/Org/Wordlist)</strong></td><td>Secret detection, wordlist generation, and org-wide scanning via trufflehog and gh CLI</td><td>Source code and org monitoring</td></tr><tr><td><strong>Monitoring</strong></td><td>Periodic re-scans for changes or new findings</td><td>Continuous program intelligence</td></tr></tbody></table>

***

### **Mobile Pipelines**

#### **Android (APKX)**

* Orchestrated via n8n to the APKX backend.
* **Analysis capabilities:** 1600+ security patterns, exported components review, deep links, insecure storage, cert pinning, debug mode, Janus vulnerability detection.
* **Operational features:** Queueing, intelligent caching, multi-store downloads (APKPure, Play Store, F-Droid, AppGallery), optional MITM patching, and HTML/JSON reporting.
* **Storage:** GitLab integration for zero-local storage and automatic synchronization.
* Status updates and completions are tracked in Notion and broadcast to Discord.

#### **iOS (APKX iOS)**

* Similar orchestration with capacity checks, job submission, and reporting.
* **Capabilities:** IPA analysis, plist parsing, ATS review, jailbreak detection, keychain inspection, and binary analysis.
* **Download:** ipatool integration with authenticated access.
* **Storage:** GitLab-backed artifact management.

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

***

### **Tooling Ecosystem**

* **Subdomain/Host:** subfinder, httpx, dnsx
* **Ports:** naabu
* **Vulnerability Templates:** nuclei (public/custom)
* **Web Vulns:** Dalfox, GF patterns, reflection checks
* **Content Discovery:** ffuf, fuzzuli
* **GitHub:** trufflehog, gh CLI, raw REST fallback
* **Mobile:** APKX pipelines for Android/iOS

***

### **Discord Integration**

* **Notifications:** Capacity warnings, completion summaries, and error alerts.
* **Artifact Sharing:** Wordlists, secrets, and scan summaries via file attachments.
* **APKX Reports:** Mobile HTML/JSON results posted with download links.
* **Rich Embeds:** Structured messages containing metadata and findings counts.
* **Webhooks:** Per-scan configuration for targeted reporting.

***

### **Why This Automation Works**

* **Consistency:** Every run is defined, logged, and repeatable.
* **Scale:** Capacity checks prevent overload and ensure reliable throughput.
* **Speed:** One action in Notion triggers the full automation chain.
* **Signal Over Noise:** Discord carries essential alerts; Notion holds structured data.
* **Extensibility:** New tools are simple new nodes or API routes.
* **Quality:** AI-assisted reporting enforces structured documentation with minimal manual overhead.

***

### **Outcome**

This architecture transforms reconnaissance and analysis into a **controlled, repeatable system**. **n8n orchestrates**, **AutoAR executes**, **Notion tracks**, **Discord informs**, and **AI accelerates reporting** — creating a professional, maintainable, and extensible foundation for modern bug bounty operations.
