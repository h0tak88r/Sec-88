**Web Cache Deception**

- [ ] [**Check HTTP headers**](https://github.com/carlospolop/hacktricks/blob/master/network-services-pentesting/pentesting-web/special-http-headers.md#cache-headers)
- [ ] [**Identify and evaluate unkeyed inputs**](https://github.com/M8SZT8/Security-Hub/blob/main/web-cache-bugs/README.md#discovery-identify-and-evaluate-unkeyed-inputs)
- [ ] **Use** **[Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)** **→** `wcvs -u` [`https://example.com`](https://example.com)

**Web Cache Deception**

To test for web cache deception try one of the several path confusing payloads as shown below:  
● [example.com/nonexistent.css](http://example.com/nonexistent.css)  
● [example.com/%0nonexistent.css](http://example.com/%0Anonexistent.css)  
● [example.com/%3Bnonexistent.css](http://example.com/%3Bnonexistent.css)  
● [example.com/%23nonexistent.css](http://example.com/%23nonexistent.css)  
● [example.com/%3Fname=valnonexistent.css](http://example.com/%3fname=valnonexistent.css)

**•** **_Use less known extensions such as_** **`.avif`**

`chat.openai[.]com/api/auth/session.css` → 400

`chat.openai[.]com/api/auth/session/test.css` → 200

[Omer Gil: Web Cache Deception Attack](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)

# Cache Poisoning and Cache Deception

## The difference

> What is the difference between web cache poisoning and web cache deception?
> 
> - In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
> - In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

## References

- [https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- **hacktricks** -> [https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/cache-deception.md)
- [https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities](https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities)
- [https://hackerone.com/reports/593712](https://hackerone.com/reports/593712)
- [https://youst.in/posts/cache-poisoning-at-scale/](https://youst.in/posts/cache-poisoning-at-scale/)
- [https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)