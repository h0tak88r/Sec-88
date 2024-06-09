---
description: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
---

# Bypassing SameSite Cookie Restrictions

1. **Introduction to SameSite Cookies**:
   * SameSite is a browser security mechanism that determines when a website's cookies are included in requests originating from other websites.
   * It provides partial protection against cross-site attacks like CSRF, cross-site leaks, and some CORS exploits.
2. **Understanding SameSite Terminology**:
   * A "site" refers to the top-level domain (TLD) plus one additional level of the domain name.
   * An "origin" includes one domain name, determined by scheme, domain name, and port.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Difference between origin and site</p></figcaption></figure>

| **Request from**          | **Request to**                 | **Same-site?**        | **Same-origin?**           |
| ------------------------- | ------------------------------ | --------------------- | -------------------------- |
| `https://example.com`     | `https://example.com`          | Yes                   | Yes                        |
| `https://app.example.com` | `https://intranet.example.com` | Yes                   | No: mismatched domain name |
| `https://example.com`     | `https://example.com:8080`     | Yes                   | No: mismatched port        |
| `https://example.com`     | `https://example.co.uk`        | No: mismatched eTLD   | No: mismatched domain name |
| `https://example.com`     | `http://example.com`           | No: mismatched scheme | No: mismatched scheme      |

1. **How SameSite Works**:
   * Before SameSite, browsers sent cookies in every request to the domain that issued them.
   * SameSite enables limiting which cross-site requests should include specific cookies.
   * Major browsers support three SameSite restriction levels: Strict, Lax, and None.
2. **Types of SameSite Restrictions**:
   * Strict: Cookies are not sent in any cross-site requests.
   * Lax: Cookies are sent in cross-site GET requests triggered by top-level navigations.
   * None: Cookies are sent in all cross-site requests.
3. **Bypassing SameSite Lax Restrictions**:
   *   Using GET requests: By eliciting a GET request from the victim's browser, even if the request involves a top-level navigation.



       ```html
       <script>
           document.location = '<https://vulnerable-website.com/account/transfer-payment?recipient=hacker&amount=1000000>';
       </script>
       ```



       ```html
       <!--
       	Bypass using Symfoney framework
       	Symfony supports the _method parameter in forms
       	which takes precedence over the normal method for routing purposes: 
       -->
       <form action="<https://vulnerable-website.com/account/transfer-payment>" method="POST">
           <input type="hidden" name="_method" value="GET">
           <input type="hidden" name="recipient" value="hacker">
           <input type="hidden" name="amount" value="1000000">
       </form>
       ```
   * Using on-site gadgets: Finding gadgets like client-side redirects within the same site to bypass restrictions.
   * Via vulnerable sibling domains: Auditing all available attack surfaces, including sibling domains\[subdomains], for vulnerabilities.
4.  With newly issued cookies: Exploiting a two-minute window where Lax restrictions aren't enforced for top-level POST requests.



    **To bypass SameSite Lax restrictions with newly issued cookies:**

    * Typically, cookies with Lax SameSite restrictions aren't sent in cross-site POST requests, except for some scenarios.
    * Chrome doesn't enforce Lax restrictions for the first 120 seconds on top-level POST requests to prevent issues with single sign-on (SSO) mechanisms.
    * Exploiting this window involves finding a way to force the user's browser to issue a new session cookie.
    * One method is to trigger a cookie refresh during a top-level navigation, such as completing an OAuth-based login flow, ensuring the inclusion of current session cookies.
    * Another method is triggering the refresh from a new tab to avoid leaving the page, though browsers may block popup tabs unless opened manually.
    * To overcome this blocking, you can wrap the window.open() method in an onclick event handler so that it only activates upon user interaction.
5. **Conclusion and Resources**:
   * SameSite cookies provide security against cross-site attacks but can be bypassed using various techniques.
   * Developers and testers need to be aware of these bypass methods to thoroughly test for vulnerabilities.
