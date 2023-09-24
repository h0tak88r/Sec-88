## Intro

API3:2023 Broken Object Property Level Authorization (BOPLA) is the combination of two items from the 2019 OWASP API Security Top Ten, excessive data exposure and mass assignment.

Excessive Data Exposure takes place when an API provider responds to a request with an entire data object. Usually, an API provider will filter out the data object down to what is being requested. When the data object is shared without being filtered there is an increased risk of exposing sensitive information.

Mass Assignment is a weakness that allows for user input to alter sensitive object properties. If, for example, an API uses a special property to create admin accounts only authorized users should be able to make requests that successfully alter those administrative properties. If there are no restrictions in place then an attacker would be able to elevate their privileges and perform administrative actions.

Both of these vulnerabilities involved issues with object property authorization, so they were combined under the new title of Broken Object Property Level Authorization.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)

_APIs tend to expose endpoints that return all object’s properties. This is particularly valid for REST APIs. For other protocols such as GraphQL, it may require crafted requests to specify which properties should be returned. Identifying these additional properties that can be manipulated requires more effort, but there are a few automated tools available to assist in this task._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)

_Inspecting API responses is enough to identify sensitive information in returned objects’ representations. Fuzzing is usually used to identify additional (hidden) properties. Whether they can be changed is a matter of crafting an API request and analyzing the response. Side-effect analysis may be required if the target property is not returned in the API response._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)

_Unauthorized access to private/sensitive object properties may result in data disclosure, data loss, or data corruption. Under certain circumstances, unauthorized access to object properties can lead to privilege escalation or partial/full account takeover._

## Summary

Broken Object Property Level Authorization (BOPLA) is a combination of Mass Assignment and Excessive Data Exposure. In the [2023 release notes](https://owasp.org/API-Security/editions/2023/en/0x04-release-notes/) the security project states, that these two vulnerabilities were combined "focusing on the common root cause: object property level authorization validation failures".

The OWASP API Security Project states that an API endpoint is vulnerable if:

- The API endpoint exposes properties of an object that are considered sensitive and should not be read by the user. (previously named: "[Excessive Data Exposure](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md)")
- The API endpoint allows a user to change, add/or delete the value of a sensitive object's property which the user should not be able to access (previously named: "[Mass Assignment](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa6-mass-assignment.md)")

Excessive data exposure is when an API endpoint responds with more information than is needed to fulfill a request. This often occurs in cases when the provider expects the API consumer to filter results; when a consumer requests specific information, the provider might respond with all sorts of information, assuming the consumer will then remove any data they don’t need from the response. When this vulnerability is present, it can be the equivalent of asking someone for their name and having them respond with their name, date of birth, email address, phone number, and the identification of every other person they know.

For example, if an API consumer requests information for their user account and receives information about other user accounts as well, the API is exposing excessive data.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/1Zyr5SxHSgq1IBYjv1J9_UsingAPI4.PNG)

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/lkwPK1QOTuhy0sOGGoGT_UsingAPI5.PNG)

Excessive data exposure is one of those API vulnerabilities that can bypass every security control in place to protect sensitive information and hand it all to an attacker on a silver platter simply because they used the API. All you need to do to detect excessive data exposure is test your target API endpoints and review the information sent in response.

## Mass Assignment

Mass assignment occurs when an API consumer includes more parameters in its requests than the application intended and the application adds these parameters to code variables or internal objects. In this situation, a consumer may be able to edit object properties or escalate privileges.

For example, an application might have account update functionality that the user should use only to update their username, password, and address. If the consumer can include other parameters in a request related to their account, such as the account privilege level or sensitive information like account balances, and the application accepts those parameters without checking them against a whitelist of permitted actions, the consumer could take advantage of this weakness to change these values.

Imagine an API is called to create an account with parameters for “User” and “Password”:
```json
{

“User”: “hapi_hacker”,

“Password”: “GreatPassword123”

}
```


While reading the API documentation regarding the account creation process, say an attacker discovers that there is an additional properties, “isAdmin” that the API provider uses to create administrative accounts. An attacker could add this to a request and set the value to true:
```json
{

“User”: “hapi_hacker”,

“Password”: “GreatPassword123”,

“isAdmin”: true

}
```

If the API does not sanitize the request input, it is vulnerable to mass assignment, and an attacker could use the request to create an admin account. On the back end, the vulnerable web app will add the key-value attribute {“isAdmin”:“true”} to the user object and make the user the equivalent of an administrator.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/uyN67TJTNe36mLlcH6Tw_MA6.PNG)

Mass assignment vulnerabilities can be tested by finding sensitive parameters in API documentation and then adding those parameters to a request. Subsequent requests could then reveal if object properties have been manipulated.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)

- _When exposing an object using an API endpoint, always make sure that the user should have access to the object's properties you expose._
- _Avoid using generic methods such as to_json() and to_string(). Instead, cherry-pick specific object properties you specifically want to return._
- _If possible, avoid using functions that automatically bind a client's input into code variables, internal objects, or object properties ("Mass Assignment")._
- _Allow changes only to the object's properties that should be updated by the client._
- _Implement a schema-based response validation mechanism as an extra layer of security. As part of this mechanism, define and enforce data returned by all API methods._
- _Keep returned data structures to the bare minimum, according to the business/functional requirements for the endpoint._

## Additional Resources

- [API3:2019 Excessive Data Exposure - OWASP API Security Top 10 2019](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md)
- [API6:2019 - Mass Assignment - OWASP API Security Top 10 2019](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa6-mass-assignment.md)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-213: Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)