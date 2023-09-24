## Intro

API9:2023 Improper Inventory Management represents the risks involved with exposing non-production and unsupported API versions. When this is present the non-production and unsupported versions of the API are often not protected by the same security rigor as the production versions. This makes improper inventory management a gateway to other API security vulnerabilities.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)

_Threat agents usually get unauthorized access through old API versions or endpoints left running unpatched and using weaker security requirements. Alternatively, they may get access to sensitive data through a 3rd party with whom there's no reason to share data with._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)

_Outdated documentation makes it more difficult to find and/or fix vulnerabilities. Lack of assets inventory and retirement strategies leads to running unpatched systems, resulting in leakage of sensitive data. It's common to find unnecessarily exposed API hosts because of modern concepts like microservices, which make applications easy to deploy and independent (e.g. cloud computing, K8S). Simple Google Dorking, DNS enumeration, or using specialized search engines for various types of servers (webcams, routers, servers, etc.) connected to the internet will be enough to discover targets._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)

_Attackers can gain access to sensitive data, or even take over the server. Sometimes different API versions/deployments are connected to the same database with real data. Threat agents may exploit deprecated endpoints available in old API versions to get access to administrative functions or exploit known vulnerabilities._

## Summary

Improper inventory management takes place when an organization exposes APIs that are unsupported or still in development. As with any software, old API versions are more likely to contain vulnerabilities because they are no longer being patched and upgraded. Likewise, APIs that are still being developed are typically not as secure as their production API counterparts.

Improper inventory management can lead to other vulnerabilities, such as excessive data exposure, information disclosure, mass assignment, improper rate-limiting, and API injection. For attackers, this means that discovering an improper inventory management vulnerability is only the first step toward further exploitation of an API.

Detecting improper inventory management can be tested by using outdated API documentation, changelogs, and version history on repositories. For example, if an organization’s API documentation has not been updated along with the API’s endpoints, it could contain references to portions of the API that are no longer supported. Organizations often include versioning information in their endpoint names to distinguish between older and newer versions, such as /v1/, /v2/, /v3/, and so on. APIs still in development often use paths such as /alpha/, /beta/, /test/, /uat/, and /demo/. If an attacker knows that an API is now using apiv3.org/admin but part of the API documentation refers to apiv1.org/admin, they could try testing different endpoints to see if apiv1 or apiv2 are still active. Additionally, the organization’s changelog may disclose the reasons why v1 was updated or retired. If an attacker has access to v1, you can test for those weaknesses.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/FGPF2fPT8ysfQHtTHQbk_Wayback1.PNG)

Outside of using documentation, an attacker could discover improper inventory vulnerabilities through the use of guessing, fuzzing, or brute force requests. Testing for Improper Assets Management is all about discovering unsupported and non-production versions of an API. API providers will often update services and the newer version of the API will be available over a new path like the following:

- api.target.com/v3
- /api/v2/accounts
- /api/v3/accounts
- /v2/accounts

API versioning could also be maintained as a header:

- _Accept: version=2.0_
- _Accept api-version=3_

In addition versioning could also be set within a query parameter or request body.

- /api/accounts?ver=2
- POST /api/accounts  
      
    {  
    "ver":1.0,  
    "user":"hapihacker"  
    }

Non-production versions of an API include any version of the API that was not meant for end-user consumption. Non-production versions could include:

- api.test.target.com
- api.uat.target.com
- beta.api.com
- /api/private
- /api/partner
- /api/test

In these instances, earlier versions of the API may no longer be patched or updated. Since the older versions lack this support, they may expose the API to additional vulnerabilities and lead an attacker to a path that can be used to compromise the provider's data. 

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)

- _Inventory all API hosts and document important aspects of each one of them, focusing on the API environment (e.g., production, staging, test, development), who should have network access to the host (e.g., public, internal, partners) and the API version._
- _Inventory integrated services and document important aspects such as their role in the system, what data is exchanged (data flow), and its sensitivity._
- _Document all aspects of your API such as authentication, errors, redirects, rate limiting, cross-origin resource sharing (CORS) policy and endpoints, including their parameters, requests, and responses._
- _Generate documentation automatically by adopting open standards. Include the documentation build in your CI/CD pipeline._
- _Make API documentation available to those authorized to use the API._
- _Use external protection measures such as API security firewalls for all exposed versions of your APIs, not just for the current production version._
- _Avoid using production data with non-production API deployments. If this is unavoidable, these endpoints should get the same security treatment as the production ones._
- _When newer versions of APIs include security improvements, perform risk analysis to make the decision of the mitigation actions required for the older version: for example, whether it is possible to backport the improvements without breaking API compatibility or you need to take the older version out quickly and force all clients to move to the latest version._

## Additional Resources

- [CWE-1059: Incomplete Documentation](https://cwe.mitre.org/data/definitions/1059.html)
- [OpenAPI Initiative](https://www.openapis.org/)