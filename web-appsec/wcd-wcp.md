---
description: 'CWE-524: Use of Cache Containing Sensitive Information'
---

# Web Caching Vulnerabilities

## Intro&#x20;

Web caching is a technique used to improve the performance and efficiency of websites by storing copies of frequently accessed content closer to the user. Instead of generating the same content repeatedly, cache servers store this content and deliver it directly to users upon subsequent requests. This reduces the load on the web server, decreases response times, and conserves bandwidth. Caching can occur at various levels, such as within a Content Delivery Network (CDN), in a browser, or at an intermediary proxy.

However, if caching is misconfigured or vulnerable, attackers can exploit it to manipulate cached content, bypass security policies, or cause sensitive information to be stored and served to unintended users. This introduces a range of security risks known as web cache vulnerabilities. Understanding how caching works is essential to identifying and mitigating these vulnerabilities.

## key Concepts

* **Cache Buster:** Technique to force the cache server to load the latest version from the web server.
* **Cache Key:** A unique identifier for cached responses, created from request parameters.
* **Web Server:** Back-end (application framework).
* **Cache Server:** Front-end (e.g., CDN like Akamai, Cloudflare).

## Caching flow&#x20;

### If cache key not exist

<figure><img src="../.gitbook/assets/image (283).png" alt=""><figcaption></figcaption></figure>

### If Exist

<figure><img src="../.gitbook/assets/image (285).png" alt=""><figcaption></figcaption></figure>

## Cache Keys in common CDNs

> _**Cache Key :** unique identifier for a request in the cache server e.g._

* **Akamai**

<figure><img src="../.gitbook/assets/image (286).png" alt=""><figcaption></figcaption></figure>

* **Cloudflare**

<figure><img src="../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

## Testing Web Cache Vulnerabilities:

1. **Cache Key Variation:** Ensure each request has a different cache key by analyzing cache-related headers (e.g., `Age`, `X-Cache`, `Cf-Cache-Status`).
2. **Cacheable Responses:** Investigate if the response is cacheable based on user input, CSRF tokens, or query parameters.
   * Tools: Burp Suite with Reshaper extension for identifying cacheable responses.
3. **Header Fuzzing:**
   * Test headers with different cases, variations (`X-Forwarded-Host`, `X_Forwarded_Host`, etc.), and multiple headers to find unkeyed headers that might result in cache poisoning.
   * Headers like `X-Forwarded-Host` can sometimes be unkeyed, leading to vulnerabilities like stored XSS or open redirection.

\*\*Bypasses

```
X-Forwarded-Host
X-FORWARDED-HOST
x-forwarded-host
X_Forwarded_Host
X-Forwarded-Host :

//  Double Header
X-Forwarded-Host
X-Forwarded-Host
```

4. **Query Parameter Fuzzing:**&#x46;ocus on unkeyed query parameters (e.g., `utm_.*`, `_method`) that the cache server ignores but the web server processes, leading to potential XSS, DoS, or information leakage.
5.  **FatGet:** Handling GET method with a body&#x20;

    <figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

    <figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
6.  **Cache Key Normalization:** Handling unencoding of special characters&#x20;

    <figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
7.  **Path Traversal:** Test for path traversal (`../`, `..%2F`, etc.) to manipulate cache paths and cache sensitive responses.

    ### ⚠️ Static Cache Response OR Dynamic Cache Response ! <a href="#id-552e" id="id-552e"></a>

    > _**Some web administrator configure CDNs to cache e.g. path/\* so we can use this to cache something not cacheable e.g. user info OR self-XSS**_

    <figure><img src="../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
8.  **Self Bugs + Senseetive response -> Cache Deception**

    &#x20;`.js->file.js-> /.js-> /file.js->.css`\
    &#x20;

    <figure><img src="../.gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
9.  **Special Characters and Delimiters:**

    ```
    user\xFUZZ
    user\xFUZZ.js
    user%FUZZ
    user%FUZZ.js
    user%25%FUZZ
    user%25%FUZZ.js
    user%25%25%FUZZ
    user%25%25%FUZZ.js
    user%FUZZ%FUZZ
    user%FUZZ%FUZZ.js
    ```

    * Delimiter: Specify boundaries between different elements in URLs e.g. `;` OR `%00` OR `%0d` OR `%0a` OR `%09` etc
    * Use delimiters like `;`, `%00`, `%0d` to exploit discrepancies between how cache and origin servers parse requests, leading to cache poisoning.
    *   Discrepancies in how the cache and origin server use characters and strings as delimiters can result in cache deception .\


        <figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>
10. **Delimiter discrepancies lead to cache deception:** if there is a delimiter I can trick a cache server to cache uncacheable response .\


    <figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption><p><a href="https://x.com/_ayoubfathi_/status/1639637351042359296">https://x.com/_ayoubfathi_/status/1639637351042359296<br></a></p></figcaption></figure>



    <figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

    <figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>
11. **Chain** Delimiter discrepancies AND Path traversal -> Cache Deception

    <figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

    <figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

    <figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>
12. **Testing for DoS:** Exploit cache poisoning for DoS by forcing the cache to serve incorrect or error responses, such as caching empty responses or invalid status codes.

## Tools & Extensio&#x6E;**:**

* **Randomizer:** For generating random tokens in requests to help as a cache buster.
  * Burp session configurations&#x20;

<figure><img src="../.gitbook/assets/image (288).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (289).png" alt=""><figcaption></figcaption></figure>

* **Burpsuite AND** **Reshaper:** For highlighting cacheable responses.

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Configure burpsuite to add custom columns using bambada code e.g.

> _**Age**_\
> &#xNAN;_**Cf-Cache-Status**_\
> &#xNAN;_**X-Cache**_
>
> _**X-Cacheable**_

{% embed url="https://miro.medium.com/v2/resize:fit:4800/format:webp/1*BZrOrjpUh0_YJbgCRupM-w.png" %}

{% embed url="https://miro.medium.com/v2/resize:fit:2000/format:webp/1*jz1mO6S6slTEjSLenyvYOA.png" %}

* **Intruder with NULL payloads:** For testing short cache durations (under 5 seconds).

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* **CDN Headers for Debugging:**
  * Akamai: `Pragma: akamai-x-check-cacheable`
  * Cloudflare: `Fastly-Debug: 1`

**Web Cache Deception**

To test for web cache deception try one of the several path confusing payloads as shown below:\
● [example.com/nonexistent.css](http://example.com/nonexistent.css)\
● [example.com/%0nonexistent.css](http://example.com/nonexistent.css)\
● [example.com/%3Bnonexistent.css](http://example.com/%3Bnonexistent.css)\
● [example.com/%23nonexistent.css](http://example.com/%23nonexistent.css)\
● [example.com/%3Fname=valnonexistent.css](http://example.com/%3fname=valnonexistent.css)

**•** _**Use less known extensions such as**_ **`.avif`**

`chat.openai[.]com/api/auth/session.css` → 400

`chat.openai[.]com/api/auth/session/test.css` → 200

[Omer Gil: Web Cache Deception Attack](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)

## The difference

> What is the difference between web cache poisoning and web cache deception?
>
> * In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
> * In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

## Resources AND Practice Labs <a href="#id-03cd" id="id-03cd"></a>

{% embed url="https://medium.com/@0xAwali/beyond-web-caching-vulnerabilities-c617d8cdbb85" %}

**Web Cache Poisoning**

* [_**https://portswigger.net/research/practical-web-cache-poisoning**_](https://portswigger.net/research/practical-web-cache-poisoning)
* [_**https://portswigger.net/research/web-cache-entanglement**_](https://portswigger.net/research/web-cache-entanglement)

**Online Practice Labs**

* [_**https://portswigger.net/web-security/all-labs#web-cache-poisoning**_](https://portswigger.net/web-security/all-labs#web-cache-poisoning)

**Web Cache Poisoning Denial of Service**

* &#x20;[_**https://cpdos.org/**_](https://cpdos.org/)
* [_**https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning**_](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning)
* [_**https://youst.in/posts/cache-poisoning-at-scale/**_](https://youst.in/posts/cache-poisoning-at-scale/)
* [_**https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole**_](https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole)

**Web Cache Deception**

* &#x20;[_**https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari**_](https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari)\

* [_**https://www.usenix.org/conference/usenixsecurity22/presentation/mirheidari**_](https://www.usenix.org/conference/usenixsecurity22/presentation/mirheidari)
* [_**https://portswigger.net/research/gotta-cache-em-all**_](https://portswigger.net/research/gotta-cache-em-all)

**Online Practice Labs**

* &#x20;[_**https://portswigger.net/web-security/all-labs#web-cache-deception**_](https://portswigger.net/web-security/all-labs#web-cache-deception)
* [https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* **hacktricks** -> [https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md)
* [https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities](https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities)
* [https://hackerone.com/reports/593712](https://hackerone.com/reports/593712)
* [https://youst.in/posts/cache-poisoning-at-scale/](https://youst.in/posts/cache-poisoning-at-scale/)
* [https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)

## Top Web Cache reports from HackerOne:

1. [DoS on PayPal via web cache poisoning](https://hackerone.com/reports/622122) to PayPal - 811 upvotes, $9700
2. [Web cache poisoning attack leads to user information and more](https://hackerone.com/reports/492841) to Postmates - 343 upvotes, $500
3. [Web Cache Poisoning leads to Stored XSS ](https://hackerone.com/reports/1424094)to Glassdoor - 99 upvotes, $0
4. [Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS](https://hackerone.com/reports/303730) to GSA Bounty - 77 upvotes, $750
5. [https://themes.shopify.com::: Host header web cache poisoning lead to DoS](https://hackerone.com/reports/1096609) to Shopify - 72 upvotes, $2900
6. [web cache deception in https://tradus.com lead to name/user\_id enumeration and other info](https://hackerone.com/reports/537564) to OLX - 61 upvotes, $0
7. [Web Cache Poisoning leads to XSS and DoS](https://hackerone.com/reports/1621540) to Glassdoor - 55 upvotes, $0
8. [CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache Deception)](https://hackerone.com/reports/260697) to Discourse - 51 upvotes, $256
9. [Web cache deception attack on https://open.vanillaforums.com/messages/all](https://hackerone.com/reports/593712) to Vanilla - 45 upvotes, $150
10. [\[https://www.glassdoor.com\] - Web Cache Deception Leads to gdtoken Disclosure ](https://hackerone.com/reports/1343086)to Glassdoor - 43 upvotes, $0
11. [Web cache poisoning leads to disclosure of CSRF token and sensitive information](https://hackerone.com/reports/504514) to Smule - 35 upvotes, $0
12. [Web Cache Deception Attack (XSS)](https://hackerone.com/reports/394016) to Discourse - 33 upvotes, $256
13. [Web Cache Poisoning on █████ ](https://hackerone.com/reports/1183263)to U.S. Dept Of Defense - 32 upvotes, $0
14. [Web Cache Deception vulnerability on algolia.com leads to personal information leakage](https://hackerone.com/reports/1530066) to Algolia - 30 upvotes, $400
15. [Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage](https://hackerone.com/reports/1271944) to Shopify - 26 upvotes, $800
16. [Web Cache poisoning attack leads to User information Disclosure and more](https://hackerone.com/reports/631589) to Lyst - 23 upvotes, $0
17. [Web cache information leakage at sbermarket.ru](https://hackerone.com/reports/893353) to Mail.ru - 22 upvotes, $400
18. [Web Cache Deception Attack (XSS)](https://hackerone.com/reports/504261) to Algolia - 21 upvotes, $0
19. [https://help.nextcloud.com::: Web cache poisoning attack](https://hackerone.com/reports/429747) to Nextcloud - 21 upvotes, $0
20. [\[\*.rocketbank.ru\] Web Cache Deception & XSS](https://hackerone.com/reports/415168) to QIWI - 20 upvotes, $0
21. [HTTP request smuggling on Basecamp 2 allows web cache poisoning](https://hackerone.com/reports/919175) to Basecamp - 17 upvotes, $1700
22. [Web Cache Poisoning](https://hackerone.com/reports/534297) to Mail.ru - 17 upvotes, $0
23. [Web cache poisoning at www.acronis.com](https://hackerone.com/reports/1010858) to Acronis - 15 upvotes, $0
24. [Web cache deception attack - expose token information](https://hackerone.com/reports/397508) to Chaturbate - 14 upvotes, $0
25. [\[okmedia.insideok.ru\] Web Cache Poisoing & XSS](https://hackerone.com/reports/550266) to ok.ru - 13 upvotes, $0
26. [Several domains on kaspersky.com are vulnerable to Web Cache Deception attack](https://hackerone.com/reports/1185028) to Kaspersky - 13 upvotes, $0
27. [Web Cache Poisoning leading to DoS](https://hackerone.com/reports/1346618) to U.S. General Services Administration - 13 upvotes, $0
28. [Information Leakage via TikTok Ads Web Cache Deception](https://hackerone.com/reports/1484468) to TikTok - 10 upvotes, $0
29. [Web cache deception attack - expose earning state information](https://hackerone.com/reports/439021) to Semrush - 3 upvotes, $0
