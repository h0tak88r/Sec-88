# Evasive Maneuvers

## Evasive Maneuvers in API Security

### Introduction

Securing APIs often involves dealing with security controls like Web Application Firewalls (WAFs) and rate-limiting mechanisms. These controls are designed to detect and prevent malicious activities. Evading these controls requires a careful understanding of the tactics they use and applying countermeasures effectively. Here are some evasive techniques you can use:

### String Terminators

String terminators, such as null bytes and specific symbols, can be used to terminate strings in requests. If not properly filtered, they can bypass security control filters. Common string terminators include:

* `%00`
* `0x00`
* `//`
* `;`
* `%`
* `!`
* `?`
* `[]`
* `%5B%5D`
* `%09`, `%0a`, `%0b`, `%0c`, `%0e`

These can be strategically placed in the request path or POST body to attempt bypassing restrictions. For example, injecting null bytes before an SQL injection attempt may bypass input validation.

### Case Switching

Some security controls rely on the exact spelling and case of components within a request. Case switching involves altering the case of letters in the URL path or payload. For instance, if rate-limiting is in place, switching upper- and lower-case letters in the path may cause the API provider to handle the request differently, potentially bypassing rate limits. Automated tools like Burp Suite's Intruder can be used to perform case-switching attacks efficiently.

### Encoding Payloads

Encoding payloads can trick WAFs while still being processed by the target application or database. Payloads can be URL-encoded, and double encoding can be attempted. For example, a WAF may block an SQL injection attack, but encoding the payload might bypass it. Tools like Burp Suite and Wfuzz provide options for encoding payloads.

### Payload Processing with Burp Suite

Burp Suite's Intruder tool allows you to automate evasive attacks by adding payload processing rules. These rules can include prefixing, suffixing, encoding, hashing, matching, and replacing characters. For instance, if null bytes need to be added before and after a URL-encoded payload, you can create rules to encode the payload first and then add the null bytes.

### Evasion with Wfuzz

Wfuzz also supports payload processing. Different encoders can be applied to payloads, such as base64 encoding, MD5 hashing, and more. Encoders can be used individually or combined, and the results can be observed in the attack responses. Wfuzz provides flexibility in processing payloads for effective evasion.

Remember that evading security controls is a dynamic process, requiring continuous testing and adaptation to stay ahead of evolving security measures. Techniques like string terminators, case switching, and payload encoding can be powerful tools in the arsenal of an API security tester.

For a more in-depth exploration of Web Application Firewall (WAF) bypass techniques, you can refer to the Awesome-WAF GitHub repository: [Awesome-WAF](https://github.com/0xInfection/Awesome-WAF).
