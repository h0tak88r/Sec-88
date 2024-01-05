---
description: 'CWE-644: Improper Neutralization of HTTP Headers'
---

# Host Header Injection

**Where We need to look ?**

* _Reset password Functionality_
* _Signup_
* _Confirmation Token_

#### **How To Mitigate This Type Of Issue :**

_· Validate the headers that supplied into the requests Which You Must Need to configure Properly That an bad actor can’t control._

_· Also use multi-factor authentication to prevent account hijacking , and one such method is SMS Authentication._

## Checklist

* [ ] try [localhost](http://localhost)
* [ ] [**Web cache poisoning via ambiguous requests**](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-web-cache-poisoning-via-ambiguous-requests)
* [ ] Add two `HOST:` in Request.
* [ ] Try this Headers
* [ ] If you come across `/api.json` in any AEM instance during bug hunting, try for web cache poisoning via following`Host: , X-Forwarded-Server , X-Forwarded-Host:`\
  and or simply try [https://localhost/api.json](https://localhost/api.json) HTTP/1.1
* [ ] Also try `Host: redacted.com.evil.com`
* [ ] Try Host: [evil.com/redacted.com](http://evil.com/redacted.com)[https://hackerone.com/reports/317476](https://hackerone.com/reports/317476)
* [ ] Try this too `Host: example.com?.mavenlink.com`
* [ ] Try `Host: javascript:alert(1);` Xss payload might result in debugging mode.\
  [https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html](https://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
* [ ] Host Header to Sqli\
  [https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610](https://blog.usejournal.com/bugbounty-database-hacked-of-indias-popular-sports-company-bypassing-host-header-to-sql-7b9af997c610)
* [ ] Bypass front server restrictions and access to forbidden files and directories through
* [ ] Add line wrapping
* [ ] Supply an absolute URL

### References

* [PortSwigger](https://portswigger.net/web-security/host-header/exploiting)
