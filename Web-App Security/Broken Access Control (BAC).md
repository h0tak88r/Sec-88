- [ ] Unprotected admin panel [in source code or robots.txt]
- [ ] [**User role controlled by request parameter**](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)
- [ ] [**User role can be modified in user profile**](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)
- [ ] [**User ID controlled by request parameter**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)
- [ ] [**User ID controlled by request parameter, with unpredictable user IDs**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)
- [ ] [**User ID controlled by request parameter with data leakage in redirect**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)
- [ ] [**User ID controlled by request parameter with password disclosure**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)
- [ ] [**URL-based access control can be circumvented**](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented) **[X-Original-URL:] or other headers that backend handle it to give access**
- [ ] [**Method-based access control can be circumvented**](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented) **[ Changing the method of the request ]**
- [ ] [**Multi-step process with no access control on one step**](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step) **[ Do a need-privilege action with non-privilege user even if there is confirmation step ]**
- [ ] [**Referer-based access control**](https://portswigger.net/web-security/access-control/lab-referer-based-access-control) **[ backend depends on referrer header to access the user to do sensitive actions ]**
- [ ] **improper Access generic**

 Authorization Bypass reports from HackerOne:

1. [Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO](https://hackerone.com/reports/791775) to Shopify - 1812 upvotes, $0
2. [[Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation](https://hackerone.com/reports/796808) to Shopify - 872 upvotes, $0
3. [Ability to reset password for account](https://hackerone.com/reports/322985) to Upserve  - 602 upvotes, $0
4. [Request smuggling on admin-official.line.me could lead to account takeover](https://hackerone.com/reports/740037) to LINE - 554 upvotes, $0
5. [Privilege Escalation From user to SYSTEM via unauthenticated command execution ](https://hackerone.com/reports/544928) to Ubiquiti Inc. - 540 upvotes, $0
6. [Email Confirmation Bypass in your-store.myshopify.com which leads to privilege escalation](https://hackerone.com/reports/910300) to Shopify - 533 upvotes, $0
7. [Able to Become Admin for Any LINE Official Account](https://hackerone.com/reports/698579) to LINE - 485 upvotes, $0
8. [H1514 Ability to MiTM Shopify PoS Session to Takeover Communications](https://hackerone.com/reports/423467) to Shopify - 362 upvotes, $13337
9. [Attacker is able to access commit title and team member comments which are supposed to be private](https://hackerone.com/reports/502593) to GitLab - 337 upvotes, $0
10. [[Razer Pay  Mobile App] Broken access control allowing other user's bank account to be deleted](https://hackerone.com/reports/757095) to Razer - 311 upvotes, $1000
11. [Shopify admin authentication bypass using partners.shopify.com](https://hackerone.com/reports/270981) to Shopify - 290 upvotes, $20000
12. [Oracle Webcenter Sites administrative and hi-privilege access available directly from the internet (/cs/Satellite)](https://hackerone.com/reports/170532) to LocalTapiola - 261 upvotes, $18000
13. [Team member with Program permission only can escalate to Admin permission](https://hackerone.com/reports/605720) to HackerOne - 257 upvotes, $2500
14. [Linux privilege escalation via trusted $PATH in keybase-redirector ](https://hackerone.com/reports/426944) to Keybase - 245 upvotes, $5000
15. [Bypass Email Verification -- Able to Access Internal Gitlab Services that use Login with Gitlab and Perform Check on email domain](https://hackerone.com/reports/565883) to GitLab - 237 upvotes, $0
16. [Ability to bypass partner email confirmation to take over any store given an employee email](https://hackerone.com/reports/300305) to Shopify - 230 upvotes, $15250
17. [Privilege escalation from any user (including external) to gitlab admin when admin impersonates you](https://hackerone.com/reports/493324) to GitLab - 230 upvotes, $0
18. [Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties](https://hackerone.com/reports/922456) to GitLab - 223 upvotes, $3000
19. [Unauthenticated blind SSRF in OAuth Jira authorization controller](https://hackerone.com/reports/398799) to GitLab - 222 upvotes, $4000
20. [[www.zomato.com] Blind XSS on one of the Admin Dashboard](https://hackerone.com/reports/724889) to Zomato - 213 upvotes, $750
21. [Ability to DOS any organization's SSO and open up the door to account takeovers](https://hackerone.com/reports/976603) to Grammarly - 212 upvotes, $10500
22. [Ability To Delete User(s) Account Without User Interaction](https://hackerone.com/reports/928255) to GitLab - 211 upvotes, $0
23. [Privilege escalation in workers container ](https://hackerone.com/reports/692603) to Semmle - 202 upvotes, $1500
24. [Incorrect authorization to the intelbot service leading to ticket information](https://hackerone.com/reports/1328546) to TikTok - 201 upvotes, $15000
25. [Admin Management - Login Using Default Password - Leads to Image Upload Backdoor/Shell](https://hackerone.com/reports/699030) to Razer - 199 upvotes, $200
26. [Ability to create own account UUID leads to stored XSS](https://hackerone.com/reports/249131) to Upserve  - 198 upvotes, $1500
27. [Unauthorized access to █████████.com allows access to Uber Brazil tax documents and system.](https://hackerone.com/reports/530441) to Uber - 196 upvotes, $4500
28. [HackerOne Jira integration plugin Leaked JWT to unauthorized jira users](https://hackerone.com/reports/1103582) to HackerOne - 193 upvotes, $3000
29. [Stealing Users OAuth authorization code via redirect_uri](https://hackerone.com/reports/1861974) to pixiv - 183 upvotes, $2000
30. [Unauthorized access to metadata of undisclosed reports that were retested](https://hackerone.com/reports/871749) to HackerOne - 180 upvotes, $0