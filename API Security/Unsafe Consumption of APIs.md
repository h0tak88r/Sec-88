## Intro

API10:2023 Unsafe Consumption of APIs is the only item on the top ten list that focuses less on the risks of being an API provider and more on the API consumer. Unsafe consumption is really a trust issue. When an application is consuming the data of third-party APIs it should treat those with a similar trust to user input. By that, I mean, there should be little to no trust. So, data consumed from third-party APIs should be treated with similar security standards as end-user-supplied input. If a third-party API provider is compromised then that insecure API connection back to the consumer becomes a new vector for the attacker to leverage. In the case of an insecure API connection, that could mean the complete compromise of organizations insecurely consuming data from that provider.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)

_Exploiting this issue requires attackers to identify and potentially compromise other APIs/services the target API integrated with. Usually, this information is not publicly available or the integrated API/service is not easily exploitable._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)

_Developers tend to trust and not verify the endpoints that interact with external or third-party APIs, relying on weaker security requirements such as those regarding transport security, authentication/authorization, and input validation and sanitization. Attackers need to identify services the target API integrates with (data sources) and, eventually, compromise them._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)

_The impact varies according to what the target API does with pulled data. Successful exploitation may lead to sensitive information exposure to unauthorized actors, many kinds of injections, or denial of service._

## Summary

Most of the 2023 OWASP API Security Top 10 is about APIs and the API provider. An API can often serve as the path of least resistance for an attacker. So, if an attacker compromises a third-party API provider, then that third party's connections to other businesses can become an additional attack vector. If that API is over an unencrypted connection then an attacker would be able to capture sensitive data in clear text. If that third-party API isn't held to similar security standards as an Internet-facing API then it could also be vulnerable to injection, authorization, and other compromising attacks.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)

- When evaluating service providers, assess their API security posture.
- Ensure all API interactions happen over a secure communication channel (TLS).
- Always validate and properly sanitize data received from integrated APIs before using it.
- Maintain an allowlist of well-known locations integrated APIs may redirect yours to: do not blindly follow redirects.

## Additional Resources

- [Web Service Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html)
- [Injection Flaws](https://www.owasp.org/index.php/Injection_Flaws)
- [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)