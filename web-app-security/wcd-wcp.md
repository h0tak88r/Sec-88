---
description: Web Cache Poisoning/Deception
---

# WCD - WCP

**Web Cache Deception**

* [ ] [**Check HTTP headers**](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-web/special-http-headers.md#cache-headers)
* [ ] [**Identify and evaluate unkeyed inputs**](https://github.com/M8SZT8/Security-Hub/blob/main/web-cache-bugs/README.md#discovery-identify-and-evaluate-unkeyed-inputs)
* [ ] **Use** [**Web Cache Vulnerability Scanner**](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) **→** `wcvs -u` [`https://example.com`](https://example.com)

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

## Cache Poisoning and Cache Deception

### The difference

> What is the difference between web cache poisoning and web cache deception?
>
> * In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
> * In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

### References

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
