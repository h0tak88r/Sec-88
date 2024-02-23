# XSSI (Cross Site Script Inclusion)

**Vulnerability: Cross Site Script Inclusion (XSSI)**

#### Overview:

XSSI, or Cross Site Script Inclusion, is a security vulnerability that facilitates the unauthorized leakage of sensitive data from one domain to another. This includes critical information like login credentials, tokens, cookies, session IDs, and personal user data such as mobile numbers, credit card information, emails, and addresses.

#### Understanding XSSI:

1. **Same Origin Policy (SOP):**
   * SOP restricts websites from accessing data from domains other than their own.
   * Notably, HTML `<script>` tags are exempt from SOP to enable third-party service consumption, traffic analysis, and Ad-Platform usage.
2. **Dynamic Javascript:**
   * Dynamic JavaScript code expects session tokens to fetch specific data.
   * Detection involves comparing responses from authenticated and non-authenticated requests; differing responses indicate dynamic JS.

#### XSSI Attack Scenario:

1. **Detection of Dynamic JS:**
   * Identify dynamic JS files using tools like the Burp plugin DetectDynamicJS or manual inspection.
2. **Example:**
   * A dynamic JS function, e.g., `info.js` at `https://testsite.com/info.js`, responds differently with and without session cookies.
3.  **Attack Steps:**

    * An attacker hosts a site (e.g., `attacker.com`) and injects code into its HTML.

    ```html
    <html>
      <script>
        function abc(s) {
          alert(JSON.stringify(s));
        }
      </script>
      <script src="https://vulnsite.com/p/?showinfo=abc"></script>
    </html>
    ```

    * The injected code fetches sensitive data from `https://vulnsite.com/p/?showinfo=abc` and sends it to the attacker's server.
4. **Victim Interaction:**
   * The attacker delivers the URL `https://attacker.com/index.html` to an authenticated victim.
   * Victim data is fetched, and the attacker can monitor it on their log server.

#### Remediation:

1. **Avoid Interpolating Sensitive Data:**
   * Refrain from interpolating sensitive data in JavaScript files.
2. **Use JSON URLs:**
   * Utilize JSON URLs instead of embedding sensitive data directly in JavaScript files.
3. **Avoid JSONP:**
   * Do not use JSONP, as it loads script elements and bypasses the Same Origin Policy.
4. **Content Type Consideration:**
   * Choose JSON or HTML content types, as they are subject to the browser's same-origin policy, preventing XSSI attacks.

## Reports

{% embed url="https://vulners.com/myhack58/MYHACK58:62201786491" %}
[https://hackerone.com/reports/207266](https://hackerone.com/reports/207266)
{% endembed %}

{% embed url="https://hackerone.com/reports/138270" %}

{% embed url="https://hackerone.com/reports/361951" %}

{% embed url="https://hackerone.com/reports/118631" %}

## Writeups

{% embed url="https://book.hacktricks.xyz/pentesting-web/xssi-cross-site-script-inclusion" %}

{% embed url="https://medium.com/@vflexo/hunting-for-vulnerabilities-that-are-ignored-by-most-of-the-bug-bounty-hunters-part-1-187b35508e56" %}

{% embed url="https://medium.com/@alex.birsan/the-bug-that-exposed-your-paypal-password-539fc2896da9" %}
[https://hackerone.com/reports/739737](https://hackerone.com/reports/739737)
{% endembed %}
