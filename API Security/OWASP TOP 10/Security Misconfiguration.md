## Intro

API8:2023 Security Misconfiguration represents a catch-all for many vulnerabilities related to the systems that host APIs. When an API's security is misconfigured it can be detrimental to the confidentiality, integrity, and availability of the API provider's data. Due to the wide variety of flaws that could exist, the impacts of an exploited security misconfiguration can range from information disclosure to data breach.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)

_Attackers will often attempt to find unpatched flaws, common endpoints, or unprotected files and directories to gain unauthorized access or knowledge of the system._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)

_Security misconfiguration can happen at any level of the API stack, from the network level to the application level. Automated tools are available to detect and exploit misconfigurations such as unnecessary services or legacy options._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)

_Security misconfigurations can not only expose sensitive user data, but also system details that can lead to full server compromise._

## Summary

Security misconfigurations include all the mistakes that API providers can make within the supporting systems of an API. Security misconfigurations are really a set of weaknesses that includes misconfigured headers, misconfigured transit encryption, the use of default accounts, the acceptance of unnecessary HTTP methods, a lack of input sensitization, and verbose error messaging.

For example, if the API’s supporting security configuration reveals an unpatched vulnerability, there is a chance that an attacker could leverage a published exploit to easily pwn the API and its system.

A lack of input sanitization could allow attackers to upload malicious payloads to the server. APIs often play a key role in automating processes, so imagine being able to upload payloads that the server automatically processes into a format that could be remotely executed or executed by an unsuspecting end-user.

For example, if an upload endpoint was used to pass uploaded files to a web directory, then it could allow the upload of a script. Navigating to the URL where the file is located could launch the script resulting in direct shell access to the web server.

Additionally, a lack of input sanitization can lead to unexpected behavior on the part of the application. 

API providers use headers to provide the consumer with instructions for handling the response and security requirements. Misconfigured headers can result in sensitive information disclosure, downgrade attacks, and cross-site scripting attacks. Many API providers will use additional services alongside their API to enhance API-related metrics or to improve security. It is fairly common that those additional services will add headers to requests for metrics and perhaps as some level of assurance to the consumer.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/1JfV14LsRYGj7k5utleN_Niktoscan.png)

The X-Powered-By header reveals backend technology. Headers like this one will often advertise the exact supporting service and its version. You could use information like this to search for exploits published for that version of software.

X-XSS-Protection is exactly what it looks like: a header meant to prevent cross-site scripting (XSS) attacks. XSS is a common type of injection vulnerability where an attacker could insert scripts into a web page and trick end-users into clicking on malicious links. An X-XSS-Protection value of 0 indicates no protections in place and a value of 1 indicates that the protection is turned on. This header, and others like it, clearly reveals whether or not a security control is in place.

The X-Response-Time header is middleware that provides usage metrics. In the previous example, its value represents 566.43 milliseconds. But if the API isn’t configured properly, this header can function as a side-channel used to reveal existing resources. If the X-Response-Time header has a consistent response time for non-existing records, for example, but increases its response time for certain other records, this could be an indication that those records exist.

Say, for instance, an attacker can determine that a bogus account like /user/account/thisdefinitelydoesnotexist has an average X-Response-Time of 25.5 ms. You also know that your existing account /user/account/1021 receives an X-Response-Time of 510.00. An attacker could then send requests brute forcing account numbers and review the results and see which account numbers resulted in drastically increased response times.

Any API providing sensitive information to consumers should use Transport Layer Security to encrypt the data, even if the API is only provided internally, privately, or at a partner level, Transport Layer Security, the protocol that encrypts HTTPS traffic, is one of the most basic ways to ensure that API requests and responses are protected when being passed across a network. Misconfigured or missing transit encryption can cause API users to pass sensitive API information in cleartext across networks, in which case an attacker could capture the responses and requests with a Man-in-the-Middle (MITM) attack and read them plainly. They would simply have to intercept the network traffic with a network protocol analyzer, like Wireshark, to see the information being communicated between a consumer and a provider.

When a service uses default accounts or credentials and the defaults are known, an attacker can use those credentials to assume the role of that account. This could allow them to gain access to sensitive information or administrative functionality and potentially lead to a compromise of the supporting systems.

Lastly, if an API provider allows unnecessary HTTP methods, there is an increased risk that the application won’t handle these methods properly or will result in sensitive information disclosure.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/tXyxubIySxasnFlUXUtw_ScanningAPIs5.PNG)

Out of all the vulnerabilities covered on the OWASP Top 10, API8:2023 Security Misconfiguration is one of the only ones to be detected by web application vulnerability scanners. Automated scanners like Burp Suite, Nessus, Qualys, OWASP ZAP, and Nikto will automatically check responses from the web server to determine version information, headers, cookies, transit encryption configuration, and parameters to see if expected security measures are missing. Security misconfigurations can also be checked manually, if you know what you are looking for, by inspecting the headers, SSL certificate, cookies, and parameters.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)

_The API life cycle should include:_

- _A repeatable hardening process leading to fast and easy deployment of a properly locked down environment_
- _A task to review and update configurations across the entire API stack. The review should include: orchestration files, API components, and cloud services (e.g. S3 bucket permissions)_
- _An automated process to continuously assess the effectiveness of the configuration and settings in all environments_

_Furthermore:_

- _Ensure that all API communications from the client to the API server and any downstream/upstream components happen over an encrypted communication channel (TLS), regardless of whether it is an internal or public-facing API._
- _Be specific about which HTTP verbs each API can be accessed by: all other HTTP verbs should be disabled (e.g. HEAD)._
- _APIs expecting to be accessed from browser-based clients (e.g., WebApp front-end) should, at least:_
    - _implement a proper Cross-Origin Resource Sharing (CORS) policy_
    - _include applicable Security Headers_
- _Restrict incoming content types/data formats to those that meet the business/ functional requirements._
- _Ensure all servers in the HTTP server chain (e.g. load balancers, reverse and forward proxies, and back-end servers) process incoming requests in a uniform manner to avoid desync issues._
- _Where applicable, define and enforce all API response payload schemas, including error responses, to prevent exception traces and other valuable information from being sent back to attackers._

## Additional Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Configuration and Deployment Management Testing - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
- [Testing for Error Handling - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README)
- [Testing for Cross Site Request Forgery - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
- [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
- [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final), NIST
- [Let's Encrypt: a free, automated, and open Certificate Authority](https://letsencrypt.org/)