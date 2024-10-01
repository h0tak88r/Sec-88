---
description: 'CWE-644: Improper Neutralization of HTTP Headers'
---

# Host Header Attacks

## Checklist

* [ ] [**Web cache poisoning via ambiguous requests**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)
* [ ] &#x20;[Password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
  * [ ] Add two `HOST:` in Request.
  * [ ] Try [localhost](http://localhost)
  * [ ] Try this Headers
  * [ ] If you come across `/api.json` in any AEM instance during bug hunting, try for web cache poisoning via following`Host: , X-Forwarded-Server , X-Forwarded-Host:`\
    and or simply try [https://localhost/api.json](https://localhost/api.json) HTTP/1.1
  * [ ] Also try `Host: redacted.com.evil.com`
  * [ ] Try Host: [evil.com/redacted.com](http://evil.com/redacted.com)\
    [https://hackerone.com/reports/317476](https://hackerone.com/reports/317476)
  * [ ] Try this too `Host: example.com?.mavenlink.com`
  * [ ] Try `Host: javascript:alert(1);` Xss payload might result in debugging mode.\
    [https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html](https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
  * [ ] Host Header to Sqli\
    [https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610](https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610)
  * [ ] Bypass front server restrictions and access to forbidden files and directories through
  * [ ] Add line wrapping
  * [ ] Supply an absolute URL
* [ ] [Web cache poisoning](https://portswigger.net/web-security/host-header/exploiting#web-cache-poisoning-via-the-host-header)
* [ ] [Exploiting classic server-side vulnerabilities](https://portswigger.net/web-security/host-header/exploiting#exploiting-classic-server-side-vulnerabilities)
* [ ] [Bypassing authentication](https://portswigger.net/web-security/host-header/exploiting#accessing-restricted-functionality)
* [ ] [Virtual host brute-forcing](https://portswigger.net/web-security/host-header/exploiting#accessing-internal-websites-with-virtual-host-brute-forcing)
* [ ] [Routing-based SSRF](https://portswigger.net/web-security/host-header/exploiting#routing-based-ssrf)
* [ ] [Connection state attacks](https://portswigger.net/web-security/host-header/exploiting#connection-state-attacks)

### References

* [PortSwigger](https://portswigger.net/web-security/host-header/exploiting)
