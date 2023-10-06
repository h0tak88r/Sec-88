## Intro

Business logic vulnerabilities are weaknesses within applications that are unique to the policies and features of a given API provider. The exploitation of business logic takes place when an attacker leverages misplaced trust or features of an application against the API. Identifying business logic vulnerabilities can be challenging due to the unique nature of each business. The impact of these vulnerabilities can range based on the severity of the vulnerable policy or feature. 

## Attack Vector Description

Business logic vulnerabilities are unique to each application and exploit the normal intended functioning of an application's business processes. They often require specific knowledge of the application's functionality and the flow of transactions or data. Since these vulnerabilities are specific to the business logic of each application, there's no one-size-fits-all approach to identifying them.

## Security Weakness Description

Business logic vulnerabilities arise when the assumptions and constraints of a given business process aren't properly enforced in the application's control structures. This allows users to manipulate the application's functionality to achieve outcomes that are detrimental to the business. These weaknesses typically occur when developers fail to anticipate the various ways that an application's features can be misused or when they don't consider the wider context of the business rules. This is often due to a lack of comprehensive understanding of the application's business logic, a lack of input validation, or incomplete function-level authorization checks.

## Impacts Description

Business logic vulnerabilities can cause a variety of technical impacts, depending on the specific flaw and the systems involved. These impacts can range from unauthorized access to data or functionality to a total bypass of system controls.

## Summary

Business logic vulnerabilities (also known as business logic flaws, or BLF) are intended features of an application that attackers can use maliciously. For example, if an API has an upload feature that instructs users to only upload certain encoded payloads, but doesn’t validate the encoded payloads, a user could upload any file as long as it was encoded. This would allow end users to upload and potentially execute arbitrary code, including malicious payloads.

The Experian partner API leak, in early 2021, was a great example of an API trust failure. A certain Experian partner was authorized to use Experian’s API to perform credit checks, but the partner added the API’s credit check functionality to their web application and inadvertently exposed all partner-level requests to users. This request could be intercepted when using the partner’s web application, and if it included a name and address, the Experian API would respond with the individual’s credit score and credit risk factors. One of the leading causes of this business logic vulnerability was that Experian trusted the partner to not expose the API.

Another problem with trust is that credentials, like API keys, tokens, and passwords, are constantly being stolen and leaked. When a trusted consumer’s credentials are stolen, the consumer can become a wolf in sheep’s clothing and wreak havoc. Without strong technical controls in place, business logic vulnerabilities can often have the most significant impact, leading to exploitation and compromise.

Examine an API's documentation for telltale signs of business logic vulnerabilities. Statements like the following should be indications of potential business logic flaws:

“Only use feature X to perform function Y.”

“Do not do X with endpoint Y.”

“Only admins should perform request X.”

These statements may indicate that the API provider is trusting that you won’t do any of the discouraged actions, as instructed. An attacker will easily disobey such requests to test for the presence of technical security controls.

Another business logic vulnerability comes about when developers assume that consumers will exclusively use a browser to interact with the web application and won’t capture API requests that take place behind the scenes. All it takes to exploit this sort of weakness is for an attacker to intercept requests and alter the API request before it is sent to the provider. This would allow the attacker to capture shared API keys or use parameters that could negatively impact the security of the application.

As an example, consider a web application authentication portal that a user would normally employ to authenticate to their account. Say the web application issued the following API request:

```http
POST /api/v1/login HTTP 1.1

Host: example.com

--snip--

UserId=hapihacker&password=arealpassword!&MFA=true
```

There is a chance that an attacker could bypass multifactor authentication by simply altering the parameter MFA to false.

Testing for business logic flaws can be challenging because each business is unique. Automated scanners will have a difficult time detecting these issues, as the flaws are part of the API’s intended use. You must understand how the business and API operate and then consider how an attacker could use these features to their advantage. One method of testing for business logic flaws is to study the application’s business logic with an adversarial mindset and try breaking any assumptions that have been made.

## Preventative Measures

- Use a Threat Modeling Approach: Understand the business processes and workflows your API supports. Identifying the potential threats, weaknesses, and risks during the design phase can help to uncover and mitigate business logic vulnerabilities.
    
- Reduce or remove trust relationships with users, systems, or components. Business logic vulnerabilities can be used to exploit these trust relationships, leading to broader impacts.
    
- Regular training can help developers to understand and avoid business logic vulnerabilities. Training should cover secure coding practices, common vulnerabilities, and how to identify potential issues during the design and coding phases.
- Implement a bug bounty program, third-party penetration testing, or a responsible disclosure policy. This allows security researchers, who are a step removed from the design and delivery of an application, to disclose vulnerabilities they discover in APIs.
    
# How to Test
1. Identify all of the API endpoints that allow users to perform sensitive business flows. This can be done by reviewing the API's documentation and network traffic.
2. Attempt to perform these business flows without any restrictions. For example, try to reset your password without providing any authentication credentials. Or, try to purchase a large quantity of products without any restrictions on the quantity or value of the products.
3. If you are able to perform the business flows without any restrictions, then this indicates that the API is vulnerable.

## Additional Resources

- [OWASP A04 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Business Logic Vulnerability](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- [Snyk Insecure Design](https://learn.snyk.io/lessons/insecure-design/javascript/)
- [Web Security Academy: Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)