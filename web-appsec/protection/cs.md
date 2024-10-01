# CS

## **What is CSP?**

**Content Security Policy (CSP)** is a security feature that helps mitigate certain types of attacks like **Cross-Site Scripting (XSS)**, **clickjacking**, and other code injection attacks by defining which resources are allowed to be loaded and executed on a webpage.

CSP is a header or meta tag that instructs the browser on how to handle content loading. It can restrict:

* **Scripts** (`script-src`): Controls the execution of JavaScript.
* **Styles** (`style-src`): Restricts the loading of CSS.
* **Images** (`img-src`): Controls from where images can be loaded.
* **Frames** (`frame-src`): Defines from where iframes can be loaded.

An example of a CSP header:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com; object-src 'none';
```

## **CSP Bypass using Dangling Markup**

A **dangling markup attack** is a way to bypass CSP and inject malicious code by exploiting incomplete or unclosed HTML tags in the source of a vulnerable webpage. This type of attack takes advantage of how browsers handle incomplete or "dangling" HTML structures, which can lead to executing malicious scripts without triggering CSP protections.

## **How Dangling Markup Works:**

When CSP is configured on a site, it typically blocks unauthorized scripts or inline script execution. However, if the HTML structure is improperly closed or certain elements (like `<script>` tags) are injected but not properly finished, an attacker can manipulate the DOM to execute their payload.

## **Example of a Dangling Markup Bypass:**

1. **Incomplete Tag Injection**: Let's say an attacker finds a vulnerability where they can inject a **dangling tag**, such as an incomplete `<script>` or `<img>` tag, in a URL or form field.
2.  **Inserting Unfinished HTML**: The attacker injects a **partially constructed tag** that the browser tries to complete:

    ```html
    <img src="http://malicious.com/evil.jpg"
    ```

    This HTML is injected without closing the tag properly. If the target application does not sanitize the input correctly, the browser may treat it as part of the page and attempt to complete it.
3.  **JavaScript Execution**: When the browser encounters the unclosed `<img>` tag, it might attempt to complete the tag automatically, leading to potential XSS or script execution:

    ```html
    <img src="http://malicious.com/evil.jpg"><script>alert(1)</script>
    ```

    The attacker can now execute JavaScript even though the CSP is in place, as the incomplete tag led to unintentional DOM manipulation and script injection.

## **Why CSP Doesn't Prevent This:**

* **Inline JavaScript**: If CSP is configured to block inline JavaScript using `script-src 'self';` or `script-src 'nonce-*';`, it expects inline scripts to either be completely blocked or validated by a `nonce` value. But, with dangling markup, the injection happens in such a way that the browser may consider it a part of legitimate HTML content, inadvertently executing the script.
* **DOM-Based Attacks**: Since this technique leverages DOM manipulation, it sidesteps traditional CSP directives by causing browser-level interpretation of incomplete HTML.

## **Other CSP Bypass Techniques:**

* **JSONP Hijacking**: If CSP allows external script sources (`script-src` includes a trusted external domain), JSONP endpoints on those trusted domains can be exploited to bypass the policy by injecting JavaScript.
*   **Inline Event Handlers**: If CSP is misconfigured to allow inline JavaScript, event handlers like `onclick` or `onload` attributes can still lead to XSS:

    ```html
    <img src="x" onerror="alert(1)">
    ```
* **Nonces and Hashes Misconfigurations**: If a CSP uses **nonces** or **hashes** to validate inline scripts but is improperly configured (e.g., reusing nonces across pages or allowing unsafe hashes), attackers may exploit this to run their own code.

## **Mitigating Dangling Markup:**

To prevent dangling markup attacks, developers must:

* **Properly sanitize and validate input**: Ensure all user-supplied data is sanitized to prevent injection of incomplete tags or dangerous payloads.
* **Correctly configure CSP**: Ensure CSP is correctly enforced with strong rules, such as avoiding inline scripts or using strict `script-src` policies.
* **Close all HTML tags properly**: Ensure the HTML structure of the page is always well-formed and complete, so browsers don't attempt to "auto-fix" dangling or incomplete tags.

## Reference

{% embed url="https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup" %}

{% embed url="https://www.youtube.com/watch?v=XKGjuDlx_1A" %}

