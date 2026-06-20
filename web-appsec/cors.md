---
description: 'CWE-346: Origin Validation Error'
---

# CORS

### What is CORS (cross-origin resource sharing)? <a href="#what-is-cors-cross-origin-resource-sharing" id="what-is-cors-cross-origin-resource-sharing"></a>

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain.

## Misconfigured CORS

* [ ] Use **`[CorsMe](<https://github.com/Shivangx01b/CorsMe>)`** to Check all urls `cat http_https.txt | ./CorsMe -t 70`
* [ ] `Origin:null`
* [ ] `Origin:attacker.com`
* [ ] `Origin:attacker.target.com`
* [ ] `Origin:attackertarget.com`
* [ ] `Origin:sub.attackertarget.com`
* [ ] `Origin:attacker.com and then change the method Get to post/Post to Get`
* [ ] `Origin:sub.attacker target.com`
* [ ] `Origin:sub.attacker%target.com`
* [ ] `Origin:attacker.com/target.com`
* [ ] `Origin:expected-host.com.attacker.com`
* [ ] `expected-host.computer`
* [ ] `foo@evil-host:80@expected-host`
* [ ] `foo@evil-host%20@expected-host`
* [ ] `evil-host%09expected-host`
* [ ] `127.1.1.1:80\\\\@127.2.2.2:80`
* [ ] `127.1.1.1:80:\\\\@@127.2.2.2:80`
* [ ] `127.1.1.1:80#\\\\@127.2.2.2:80`
* [ ] `ß.evil-host`
* [ ] **Method 1 ( Single\_target)**

```
Step->1. Capture the target website and spider or crawl all the website using burp.
Step->2. Use burp search look for Access-Control
Step->3. Try to add Origin Header i.e,Origin:attacker.com or Origin:null or Origin:attacker.target.com or Origin:target.attacker.com
Step->4  If origin is reflected in response means the target is vuln to CORS

```

***

* **Method 2 (Multiple)**

```
step 1-> find domains i.e subfinder -d target.com -o domains.txt
step 2-> check alive ones : cat domains.txt | httpx | tee -a alive.txt
step 3-> send each alive domain into burp i.e, cat alive.txt | parallel -j 10 curl --proxy "<http://127.0.0.1:8080>" -sk 2>/dev/null
step 4-> Repeat hunting method 1

```

### Reports

* [CORS bug on google's 404 page (rewarded)](https://medium.com/@jayateerthag/cors-bug-on-googles-404-page-rewarded-2163d58d3c8b)
* [CORS misconfiguration leading to private information disclosure](https://medium.com/@sasaxxx777/cors-misconfiguration-leading-to-private-information-disclosure-3034cfcb4b93)
* [CORS misconfiguration account takeover out of scope to grab items in scope](https://medium.com/@mashoud1122/cors-misconfiguration-account-takeover-out-of-scope-to-grab-items-in-scope-66d9d18c7a46)
* [Chrome CORS](https://blog.bi.tk/chrome-cors/)
* [Bypassing CORS](https://medium.com/@saadahmedx/bypassing-cors-13e46987a45b)
* [CORS to CSRF attack](https://medium.com/@osamaavvan/cors-to-csrf-attack-c33a595d441)
* [An unexploited CORS misconfiguration reflecting further issues](https://smaranchand.com.np/2019/05/an-unexploited-cors-misconfiguration-reflecting-further-issues/)
* [Think outside the scope advanced cors exploitation techniques](https://medium.com/@sandh0t/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
* [A simple CORS misconfiguration leaked private post of twitter facebook instagram](https://medium.com/@nahoragg/a-simple-cors-misconfig-leaked-private-post-of-twitter-facebook-instagram-5f1a634feb9d)
* [Explpoiting CORS misconfiguration](https://bugbaba.blogspot.com/2018/02/exploiting-cors-miss-configuration.html)
* [Full account takeover through CORS with connection sockets](https://medium.com/@saamux/full-account-takeover-through-cors-with-connection-sockets-179133384815)
* [Exploiting insecure CORS API api.artsy.net](https://blog.securitybreached.org/2017/10/10/exploiting-insecure-cross-origin-resource-sharing-cors-api-artsy-net)
* [Pre domain wildcard CORS exploitation](https://medium.com/bugbountywriteup/pre-domain-wildcard-cors-exploitation-2d6ac1d4bd30)
* [Exploiting misconfigured CORS on popular BTC site](https://medium.com/@arbazhussain/exploiting-misconfigured-cors-on-popular-btc-site-2aedfff906f6)
* [Abusing CORS for an XSS on flickr](https://whitton.io/articles/abusing-cors-for-an-xss-on-flickr/)
