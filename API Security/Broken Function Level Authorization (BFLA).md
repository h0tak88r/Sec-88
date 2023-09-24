## Intro

API5:2023 Broken Function Level Authorization (BFLA) is a vulnerability where API functions have insufficient access controls. Where BOLA is about access to data, BFLA is about altering or deleting data. In addition, a vulnerable API would allow an attacker to perform actions of other roles including administrative actions.

To drive the point home, a fintech API susceptible to BOLA would allow an attacker the ability to see what is in the bank account of another user, while the same API vulnerable to BFLA would allow an attacker to transfer funds from other users' accounts to their own.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)

_Exploitation requires the attacker to send legitimate API calls to an API endpoint that they should not have access to as anonymous users or regular, non-privileged users. Exposed endpoints will be easily exploited._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)

_Authorization checks for a function or resource are usually managed via configuration or code level. Implementing proper checks can be a confusing task since modern applications can contain many types of roles, groups, and complex user hierarchies (e.g. sub-users, or users with more than one role). It's easier to discover these flaws in APIs since APIs are more structured, and accessing different functions is more predictable._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)

_Such flaws allow attackers to access unauthorized functionality. Administrative functions are key targets for this type of attack and may lead to data disclosure, data loss, or data corruption. Ultimately, it may lead to service disruption._

## Summary

Broken function level authorization (BFLA) is a vulnerability where a user of one privilege level can use the API functionality of a different user, user group, or another privilege level. API providers will often have different privilege levels for different types of accounts, such as public users, merchants, partners, vendors, administrators, and so on.

BFLA can be exploited for unauthorized use of lateral functions, or a similarly privileged group, or it could be exploited for privilege escalation, where an attacker can use the functions of a more privileged group. Particularly interesting API functions to access include those that deal with sensitive information, resources that belong to another group, and administrative functionality like user account management.

If an API has different privilege levels, it may use different endpoints to perform privileged actions. For example, a bank may use the /{userid}/account/balance endpoint for a user wishing to access their account information and the /admin/account/{userid} endpoint for an administrator that needs to access user account information. If the application does not have access controls implemented correctly, an attacker will be able to perform administrative actions and perform an account takeover.

An API won’t always use administrative endpoints for administrative functionality. Instead, the functionality could be based on HTTP request methods like GET, POST, PUT, and DELETE. If a provider doesn’t restrict the HTTP methods an attacker can use, simply making an unauthorized request with a different method could indicate a BFLA vulnerability.

When testing for BFLA, look for any functionality that an attacker could use to their advantage. These functions include but are not limited to, altering user accounts, deleting user resources, and gaining access to restricted endpoints. For example, if an API gave partners the ability to add new users to the partner group but did not restrict this functionality to the specific group, any user could add themselves to any group. Moreover, if an attacker can add themselves to a group, there is a good chance that they'll be able to access that group’s resources.

 In the following request, the DELETE method has been used in place of PUT. 

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/TAMib5qQmaVM8omLOEjk_Authz12.PNG)

This request results in a telling response, "This is an admin function. Try to access the admin API". This would lead an attacker to try using an admin path in the DELETE request (/identity/api/v2/**admin**/videos/758).

 ![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/0QWlHfabSD2AxT7QJQYz_Authz13.PNG)

 The admin path and request method did not have authorization controls in place and was left vulnerable to a BFLA attack.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)

_Your application should have a consistent and easy-to-analyze authorization module that is invoked from all your business functions. Frequently, such protection is provided by one or more components external to the application code._

- _The enforcement mechanism(s) should deny all access by default, requiring explicit grants to specific roles for access to every function._
- _Review your API endpoints against function level authorization flaws, while keeping in mind the business logic of the application and groups hierarchy._
- _Make sure that all of your administrative controllers inherit from an administrative abstract controller that implements authorization checks based on the user's group/role._
- _Make sure that administrative functions inside a regular controller implement authorization checks based on the user's group and role._

## Additional Resources

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [Forced Browsing](https://owasp.org/www-community/attacks/Forced_browsing)
- "A7: Missing Function Level Access Control", [OWASP Top 10 2013](https://github.com/OWASP/Top10/raw/master/2013/OWASP%20Top%2010%20-%202013.pdf)
- [OWASP Community Guide for Access Control](https://owasp.org/www-community/Access_Control)