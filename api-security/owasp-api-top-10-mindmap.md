# OWASP API TOP 10 MindMap

### API1: Broken Object Level Authorization (BOLA)

* **Description:** API users should access only their sensitive resources. BOLA allows attackers to access other users' data.
* **Testing:** Look for resource IDs, user identifiers, usernames, JWTs, and ID-based downloadable resources.

### API2: Broken Authentication

* **Description:** Results from weak authentication mechanisms or implementation errors, leading to various vulnerabilities.
* **Testing:**
  * Weak JWT and password policies
  * Credential stuffing
  * Sensitivity in URL parameters
  * Lack of password confirmation
  * Weak encryption keys
  * Captcha attacks, API keys attacks, and token-based attacks

### API3: Broken Object Property Level Authorization

* **Description:** API exposes sensitive object properties to users, allowing unauthorized access or modification.
* **Testing:**
  * Look for leaky responses revealing victim's PII info.
  * Test the possibility of adding parameters using tools like param-miner.

### API4: Unrestricted Resource Consumption

* **Description:** Lack of restrictions on resource usage exposes APIs to DoS attacks and unnecessary financial costs.
* **Testing:**
  * Execution timeouts
  * Maximum allocable memory
  * Maximum file descriptors and processes
  * Maximum upload file size
  * Operations per client request
  * Records per page in request-response
  * Third-party service providers' spending limit

### API5: Broken Function Level Authorization (BFLA)

* **Description:** Allows unauthorized alteration or deletion of data, enabling attackers to perform actions of other roles.
* **Testing:**
  * Fuzzing for administrative functions
  * Changing request methods for sensitive calls
  * Testing anonymous user access to functions requiring authentication

### API6: Unrestricted Access to Sensitive Business Flows

* **Description:** Exposing sensitive business flows in APIs may harm the business if accessed excessively.
* **Testing:** Understand business logic, read documentation, and identify potential abuse of features.

### API7: Server Side Request Forgery (SSRF)

* **Description:** Attack where an attacker forces an API to make unintended requests to a remote server.
* **Testing:** Use tools like Burp Collaborator to test user-input URL parameters.

### API8: Security Misconfiguration

* **Description:** Security issues arise from incorrectly or insecurely configured APIs and supporting systems.
* **Testing:** Check for CORS misconfigurations, stack traces, outdated systems, exposed storage, insecure default configurations, and third-party vulnerabilities.

### API9: Improper Inventory Management

* **Description:** Exposure of unsupported or underdeveloped APIs leads to vulnerabilities, data exposure, and exploitation.
* **Testing:** Look for unsupported API versions, accounts, and endpoints. Analyze API version parameters.

### API10: Unsafe Consumption of APIs

* **Description:** Insecure consumption of APIs can lead to various attacks. Treating third-party APIs like user input is essential.
* **Testing:**
  1. Identify all consumed APIs.
  2. Analyze each API's security posture.
  3. Simulate attacks (SQLi, XSS, DoS) against the APIs.

## OWASP API top 10 Mind Map

{% embed url="https://xmind.ai/share/gJnF6CP1?xid=Q0BM9sDO" %}
OWASP TOP 10 Mind Map
{% endembed %}
