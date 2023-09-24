- [ ] [**Excessive trust in client-side controls**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls) **→ [ see if there is any params that shouldn’t be validated client side ]**
- [ ] [**High-level logic vulnerability**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level) **[it accepts negative quantities]**
- [ ] [**Inconsistent security controls**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls) **[ update email functionality misconfiguration ]**
- [ ] [**Flawed enforcement of business rules**](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules) **[ coupon code misconfiguration ]**

- **Registration Functionality**
    
    ## register vulnerability
    
    - [ ] Duplicate registration overwrite existing user
    
    ```
    1. create first account in application with email say abc@gmail.com and password2. logout of the account and create another account with same email and different password3. you can even try to change email case like from abc2gmail.com to Abc@gmail.com4. finish the creation proccess and see that it succceed5. now go back and try to login with email and the new password ,you are seccess logged in
    ```
    
    - [ ] Dos at name /password field in sign up page
    
    ```
    1. go to sign up form2. fill the form and enter a long string in password3. click on enter and you will get 500 internal server error if it is vulnerability
    ```
    
    - [ ] no rate limit at signup page
    
    ```
    1. enter your details in signuo form and submit the form2. capture the signuo request and send it to intruder3. add $$ to email parameter4. in the payload add different email address5. fire up intruder and check whether it return 200 ok
    ```
    
    - [ ] xss in username,email
    
    ```
    xss can be test in any of parameter1. payload for text field:2. payload for email field:3. you can use bypassing filter
    ```
    
    - [ ] email varification can be easily bypassed with following method
    
    ```
    1. response manipulation change the bad respone with good one like false to true2. status code manipulation change the 403 to 200
    ```
    
    - [ ] weak register implemntation
    
    ```
    1. check whether the allows disposable email addresses2. register form on non-hhtps page
    ```
    
    - [ ] weak password policy
    
    ```
    1. check whether application allows easily guessable passsword like 1234562. check if you can use username same as the email address3. check if can use password same as that email address4. improperly implemented password recovery link functionality
    ```
    
    - [ ] Path Overwrite
    
    ```
    If an application allows users to check their profile with direct path /{username} always try to signup with system reserved file names, such as index.php, signup.php, login.php, etc. In some cases what happens here is, when you signup with username: index.php, now upon visiting target.tld/index.php, your profile will comeup and occupy the index.php page of an application. Similarly, if an attacker is able to signup with username login.php, Imagine login page getting takeovered.
    ```
    
- **Reset Password Functionality**
    
    - [ ] a lot of ideas in this article by **omer hesham**
    
    ```
    <https://medium.com/bugbountywriteup/hubspot-full-account-takeover-in-bug-bounty-4e2047914ab5>
    ```
    
    - [ ] Use Your Token on Victims Email
    
    ```
    POST /reset......email=victim@gmail.com&token=$YOUR-TOKEN$
    ```
    
    - [ ] Host Header Injection
    
    ```
    POST /resetHost: attacker.com...email=victim@gmail.com
    ```
    
    - [ ] HTML injection in Host Header
    
    ```
    POST /resetHost: attacker">.com...email=victim@gmail.com
    ```
    
    - [ ] Leakage of Password reset in Referer Header
    
    ```
    Referrer: <https://website.com/reset?token=1234>
    ```
    
    - [ ] Using Companies Email
    
    ```
    While inviting users into your account/organization, you can also try inviting company emails and add anew field "password": "example123". or "pass": "example123" in the request. you may end up resetting auser passwordCompany emails can be found on target's GitHub Repos members or you can check on <http://hunter.io>. some usershave a feature to set a password for invited emails, so here we can try adding a pass parameter.If successful, we can use those credentials to login into the account, SSO integrations, support panels,etc \#BugBountyTips
    ```
    
    - [ ] CRLF in URL
    
    ```
    with CLRF: /resetPassword?0a%0dHost:atracker.tld (x-host, true-client-ip, x-forwarded...)
    ```
    
    - [ ] HTML injection in Email
    
    ```
    HTML injection in email via parameters, cookie, etc > inject image > leak the  token
    ```
    
    - [ ] Remove token
    
    ```
    <http://example.com/reset?eamil=victims@gmail.com&token=>
    ```
    
    - [ ] Change it to 0000
    
    ```
    <http://example.com/reset?eamil=victims@gmail.com&token=0000000000>
    ```
    
    - [ ] Use Null Value
    
    ```
    <http://example.com/reset?eamil=victims@gmail.com&token=Null/nil>
    ```
    
    - [ ] try an array of old tokens
    
    ```
    <http://example.com/reset?eamil=victims@gmail.com&token=[oldtoken1,oldtoken2]>
    ```
    
    - [ ] SQLi bypass
    
    ```
    try sqli bypass and wildcard or, %, *
    ```
    
    - [ ] Request Method / Content Type
    
    ```
    change request method (get, put, post etc) and/or content type (xml<>json)
    ```
    
    - [ ] Response Manipulation
    
    ```
    Replace bad response and replace with good one
    ```
    
    - [ ] Massive Token
    
    ```
    <http://example.com/reset?eamil=victims@gmail.com&token=1000000> long string
    ```
    
    - [ ] Crossdomain Token Usage
    
    ```
    If a program has multiple domains using same underlying reset mechanism, reset token generated from one domain sometimeworks in another domain too.
    ```
    
    - [ ] Leaking Reset Token in Response Body
    
    [ ] change 1 char at the begin/end to see if the token is evaluated
    
    [ ] use unicode char jutzu to spoof email address
    
    [ ] look for race conditions
    
    [ ] try to register the same mail with different TLD (.eu,.net etc)
    

1. **change the price with other price :100->50**
2. **change the price with nagative price :100->-100**
3. **change the price with other price by add nagative value: 100 ->(+-120)**
4. **change the price with other price by mult by 0.5: 100->(0.5*100)**
5. **Retrieving a Profile**
    
    ```
    For example, Jack’s profile can be fetched with id=1001 and if this valuechanged to 1089 we get another user’s information. A scanner may go on andchange the value from 1001 to **‘1001** to find SQL injection, but not to 1089 andwould miss deducing that the application is vulnerable to authorization bypass. By changing the “id” from 1001 to 1089, a pen tester can see that John’s profile , rather than Jack’s, is being displayed.
    ```
    
6. **Shopping Cart**
    
    ```
    Let us consider an online store application where customers add items to their shopping cart. The application sends the customers to a secure payment gateway where they submit their order. To complete the order, customers are required to make a credit card payment. In this shopping cart application, business logic errorsmay make it possible for attackers to bypass the authentication processes todirectly log into the shopping cart application and avoid paying for “purchased” items.
    ```
    
7. **Review Functionality**
    - Some applications have an option where verified reviews are marked with some tick or it's mentioned. Try to see if you can post a review as a Verified Reviewer without purchasing that product.
    - Some app provides you with an option to provide a rating on a scale of 1 to 5, try to go beyond/below the scale-like provide 0 or 6 or -ve.
    - Try to see if the same user can post multiple ratings for a product. This is an interesting endpoint to check for Race Conditions.
    - Try to see if the file upload field is allowing any exts, it's often observed that the devs miss out on implementing protections on such endpoints.
    - Try to post reviews like some other users.
    - Try performing CSRF on this functionality, often is not protected by tokens
8. **Coupon Code Functionality**
    - Apply the same code more than once to see if the coupon code is reusable.
    - If the coupon code is uniquely usable, try testing for Race Condition on this function by using the same code for two accounts at a parallel time.
    - Try Mass Assignment or HTTP Parameter Pollution to see if you can add multiple coupon codes while the application only accepts one code from the Client Side.
    - Try performing attacks that are caused by missing input sanitization such as XSS, SQLi, etc. on this field
    - Try adding discount codes on the products which are not covered under discounted items by tampering with the request on the server-side.
9. **Delivery Charges Abuse**
    - Try tampering with the delivery charge rates to -ve values to see if the final amount can be reduced.
    - Try checking for the free delivery by tampering with the params.
10. **Currency Arbitrage**
    - Pay in 1 currency say USD and try to get a refund in EUR. Due to the diff in conversion rates, it might be possible to gain more amount.
11. **Premium Feature Abuse**
    - Try forcefully browsing the areas or some particular endpoints which come under premium accounts.
    - Pay for a premium feature and cancel your subscription. If you get a refund but the feature is still usable, it's a monetary impact issue.
    - Some applications use true-false request/response values to validate if a user is having access to premium features or not.
    - Try using Burp's Match & Replace to see if you can replace these values whenever you browse the app & access the premium features.
    - Always check cookies or local storage to see if any variable is checking if the user should have access to premium features or not.
12. **Refund Feature Abuse**
    - Purchase a product (usually some subscription) and ask for a refund to see if the feature is still accessible.
    - Try for currency arbitrage explained yesterday.
    - Try making multiple requests for subscription cancellation (race conditions) to see if you can get multiple refunds.
13. **Cart/Wishlist Abuse**
    - Add a product in negative quantity with other products in positive quantity to balance the amount.
    - Add a product in more than the available quantity.
    - Try to see when you add a product to your wishlist and move it to a cart if it is possible to move it to some other user's cart or delete it from there.
14. **Thread Comment Functionality**
    - Unlimited Comments on a thread
    - Suppose a user can comment only once, try race conditions here to see if multiple comments are possible.
    - Suppose there is an option: comment by the verified user (or some privileged user) try to tamper with various parameters in order to see if you can do this activity.
    - Try posting comments impersonating some other users.
15. **Parameter Tampering**
    - Tamper Payment or Critical Fields to manipulate their values
    - Add multiple fields or unexpected fields by abusing HTTP Parameter Pollution & Mass Assignment
    - Response Manipulation to bypass certain restrictions such as 2FA Bypass
16. **Parameter tampering can result in product price manipulation**
    - [https://www.youtube.com/watch?v=3VMlV7j_yzg](https://www.youtube.com/watch?v=3VMlV7j_yzg)
17. **Manipulation of exam results at Semrush.Academy**
    
    - In this situation, it was possible to bypass the exam process. That is to replace the results of the exam with the correct ones and send a request to get the certificate right away. And to replace the results with the correct ones turned out, because the body of the request was json, where `1 = true`, and `empty = false`.
    
    **Steps To Reproduce:**
    
    1. Finished exams with any answers
    2. Retake exam
    3. Send the last request of our answer
    
    **Example body:**
    
18. **Authentication flags and privilege escalations at application layer.**  
    Applications have their own access control lists (ACLs) and privileges. The most critical aspect of the application related to security is authentication. An authenticated user has access to the internal pages and structures that reside behind the login section. These privileges can be maintained by the database, LDAP, file etc. If the implementation of authorization is weak, it opens up possible vulnerabilities. If these vulnerabilities are identified  
    during a test, then there is the potential for exploitation. This exploitation would likely include accessing another user’s content or becoming a higher-level user with greater permissions to do greater damage  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a proxy observe the HTTP traffic, both request and response blocks.• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name ofthe parameter and the value need to be analyzed.• If the parameter name is suspicions and suggests that it has something to do with ACL/Permission then that becomes atarget.• Once the target is identified, the next step is evaluating the value, it can be encoded in hex, binary, string, etc.. The testershould do some tampering and try to define its behavior with bit of fuzzing.• In this case, fuzzing may need a logical approach, changing bit patterns or permission flags like 1 to 0 or Y to N and soon. Some combination of bruteforcing, logical deduction and artistic tampering will help to decipher the logic. If this issuccessful then we get a point for exploitation and end up escalating privileges or bypassing authorization.
    ```
    
19. **Critical Parameter Manipulation and Access to Unauthorized Information/Content.**  
    HTTP GET and POST requests are typically accompanied with several parameters when submitted to the application. These parameters can be in the form of name/value pairs, JSON, XML etc. Interestingly, these parameters can be tampered with and guessed (predicted) as well. If the business logic of the application is processing these parameters before validating them, it can lead to information/content disclosure. This is another common business logic flaw that is easy to exploit  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a proxy, observe HTTP traffic, both request and response blocks.• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name ofthe parameter and the value need to be analyzed.• Observe the values in the traffic and look for incrementing numbers and easily guessable values across all parameters.• This parameter’s value can be changed and one may gain unauthorized access.In the above case we were able to access other users profiles
    ```
    
20. **LDAP Parameter Identification and Critical Infrastructure Access  
    **LDAP is becoming an important aspect for large applications and it may get integrated with ”single sign on” as well. Many infrastructure layer tools like Site Minder or Load Balancer use LDAP for both authentication and authorization. LDAP parameters can carry business logic decision flags and those can be abused and leveraged. LDAP filtering being done at the business application layer enable logical injections to be possible on those parameters. If the application is not doing enough validation then LDAP injection and business layer bypasses are possible.
    
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a proxy observe the HTTP traffic, both request and response blocks.• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name ofthe parameter and the value need to be analyzed.• Analyze parameters and their values, look for ON,CN,DN etc. Usually these parameters are linked with LDAP. Also lookfor the parameter taking email or usernames, these parameters can be prospective targets.• These target parameters can be manipulated and injected with “*” or any other LDAP specific filters like OR, AND etc. Itcan lead to logical bypass over LDAP and end up escalating access rights.
    ```
    
21. **Developer’s cookie tampering and business process/logic bypass.**  
    Cookies are an essential component to maintain state over HTTP. In many cases, developers are not using session cookies only, but instead are building data internally using session only variables. Application developers set new cookies on the browser at important junctures which exposes logical holes. After authentication logic sets several parameters based on credentials, developers have two options to maintain these credentials across applications. The developer can set the parameters in session variables or set cookies in the browser with appropriate values. If application developers are passing cookies, then they might be reverse engineered or have values that can be guessed/ deciphered. It can create a possible logical hole or bypass. If an attacker can identify this hole then they can exploit it with ease  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a proxy observe the HTTP traffic, both request and responseblocks.• Analyze all cookies delivered during the profiling, some of these cookies will be defined by developers and are notsession cookies defined by the web application server.• Observe cookie values in specific, look for incrementing easily guessable values across all cookies.• Cookie value can be changed and one may gain unauthorized access or logical escalation
    ```
    
22. **Business Constraint Exploitation**  
    The application’s business logic should have defined rules and constraints that are very critical for an application. If these constraints are bypassed by an attacker, then it can be exploited. User fields that have poor design or implementation are often controlled by these business constraints. If business logic is processing variables controlled as hidden values then it leads to easy discovery and exploitation. While crawling and profiling the application, one can list all these possible different values and their injection places. It is easy to browse through these hidden fields and understand their context; if context is leveraged to control the business rules then manipulation of this information can lead to critical business logic vulnerabilities.  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a proxy observe the HTTP traffic, both the request and response blocks.• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name ofthe parameter and the value need to be analyzed.• Analyze hidden parameters and their values, look for business specific calls like transfer money, max limit etc. All these parameters which are dictating a business constraint can become a target.• These target parameters can be manipulated and values can be changed. It is possible to avoid the business constraint and inject an unauthorized transaction.
    ```
    
23. **Business Flow Bypass**  
    Applications include flows that are controlled by redirects and page transfers. After a successful login, for example, the application will transfer the user to the money transfer page. During these transfers, the user’s session is maintained by a session cookie or other mechanism. In many cases,  
    this flow can be bypassed which can lead to an error condition or information leakage. This leakage can help an attacker identify critical back-end information. If this flow is controlling and giving critical information out then it can be exploited in various use cases and scenarios  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a proxy observe the HTTP traffic, both request and response blocks.• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both the name of the parameter and the value need to be analyzed.• Identify business functionalities which are in specific steps (e.g. a shopping cart or wire transfer).• Analyze all steps carefully and look for possible parameters which are added by the application either using hidden values or through JavaScript.• These parameters can be tampered through a proxy while making the transaction. This disrupts the flow and can end up  bypassing some business constraints.
    ```
    
24. **Identity or Profile Extraction  
    **A user’s identity is one of the most critical parameters in authenticated applications. The identities of users are maintained using session or other forms of tokens. Poorly designed and  
    developed applications allow an attacker to identify these token parameters from the client side and in some cases they are not closely maintained on the server side of the session as well. This scenario opens up a potential opportunity for abuse and system wide exploitation. The  
    token is either using only a sequential number or a guessable username  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through particular proxy observe HTTP traffic, both request and response blocks.• POST/GET requests would have typical parameters either in name-value pair, JSON, XML or Cookies. Both name of  parameter and value need to be analyzed.• Look for parameters which are controlling profiles.• Once these target parameters are identified, one can decipher, guess or reverse engineer tokens. If tokens are guessed  and reproduced – game over!
    ```
    
25. **File or Unauthorized URL Access and Business Information Extraction Identity**  
    Business applications contain critical information in their features, in the files that are exported and in the export functionality itself. A user can export their data in a selected file format (PDF, XLS or CSV) and download it. If this functionality is not carefully implemented, it can enable asset leakage. An attacker can extract this information from the application layer. This is one of the most common mistakes and easy to exploit as well. These files can be fetched directly  
    from URLs or by using some internal parameters.  
    _**How to test for this business logic flaw:**_
    
    ```
    • During the profiling phase or through a particular proxy, observe the HTTP traffic, both request and response blocks.• POST/GET requests would have typical parameters either in a name-value pair, JSON, XML or Cookie. Both the name of parameter and value need to be analyzed.• Identify file call functionalities based on parameter names like file, doc, dir etc. These parameters will point you to possible unauthorized file access vulnerabilities.• Once a target parameter has been identified start doing basic brute force or guess work to fetch another user’s files  from server.
    ```
    
26. **null** payloads in change password try to **delete current password** `**%00**`

# Top Business Logic reports from HackerOne:

1. [Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests](https://hackerone.com/reports/689314) to GitLab - 438 upvotes, $12000
2. [Account takeover through the combination of cookie manipulation and XSS](https://hackerone.com/reports/534450) to Grammarly - 253 upvotes, $2000
3. [Ethereum account balance manipulation](https://hackerone.com/reports/300748) to Coinbase - 251 upvotes, $10000
4. [SSRF leaking internal google cloud data through upload function [SSH Keys, etc..]](https://hackerone.com/reports/549882) to Vimeo - 248 upvotes, $5000
5. [Account Takeover via Email ID Change and Forgot Password Functionality](https://hackerone.com/reports/1089467) to New Relic - 210 upvotes, $2048
6. [Blind SQL injection and making any profile comments from any users to disappear using "like" function (2 in 1 issues)](https://hackerone.com/reports/363815) to Pornhub - 208 upvotes, $2500
7. [Abusing "Report as abuse" functionality to delete any user's post.](https://hackerone.com/reports/411075) to Vanilla - 159 upvotes, $300
8. [OLO Total price manipulation using negative quantities](https://hackerone.com/reports/364843) to Upserve - 144 upvotes, $3500
9. [Unserialize leading to arbitrary PHP function invoke](https://hackerone.com/reports/210741) to Rockstar Games - 113 upvotes, $5000
10. [HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function](https://hackerone.com/reports/1478633) to Cloudflare Public Bug Bounty - 105 upvotes, $6000
11. [Null pointer dereference in SMTP server function smtp_string_parse](https://hackerone.com/reports/827729) to Open-Xchange - 105 upvotes, $1500
12. [XXE in Site Audit function exposing file and directory contents](https://hackerone.com/reports/312543) to Semrush - 99 upvotes, $2000
13. [Claiming the listing of a non-delivery restaurant through OTP manipulation](https://hackerone.com/reports/1330529) to Zomato - 85 upvotes, $3250
14. [Bypass of biometrics security functionality is possible in Android application (com.shopify.mobile)](https://hackerone.com/reports/637194) to Shopify - 73 upvotes, $500
15. [Old WebKit HTML agent in Template Preview function has multiple known vulnerabilities leading to RCE](https://hackerone.com/reports/520717) to Lob - 68 upvotes, $1500
16. [Parameter Manipulation allowed for viewing of other user’s teavana.com orders](https://hackerone.com/reports/141090) to Starbucks - 66 upvotes, $6000
17. [Authorization Token on PlayStation Network Leaks via postMessage function](https://hackerone.com/reports/826394) to PlayStation - 64 upvotes, $1000
18. [Manipulating response leads to free access to Streamlabs Prime](https://hackerone.com/reports/1070510) to Logitech - 60 upvotes, $200
19. [[api.tumblr.com] Denial of Service by cookies manipulation](https://hackerone.com/reports/1005421) to Automattic - 51 upvotes, $200
20. [SSRF in VCARD photo upload functionality](https://hackerone.com/reports/296045) to Open-Xchange - 49 upvotes, $850
21. [Captcha bypass for the most important function - At en.instagram-brand.com](https://hackerone.com/reports/206653) to Automattic - 48 upvotes, $150
22. [Stored XSS in photo comment functionality](https://hackerone.com/reports/172227) to Pornhub - 44 upvotes, $1500
23. [[intensedebate.com] No Rate Limit On The report Functionality Lead To Delete Any Comment When it is enabled](https://hackerone.com/reports/1051734) to Automattic - 43 upvotes, $200
24. [SSRF in the application's image export functionality](https://hackerone.com/reports/816848) to Visma Public - 42 upvotes, $250
25. [Able to steal private files by manipulating response using Compose Email function of Lark](https://hackerone.com/reports/1373784) to Lark Technologies - 41 upvotes, $2000
26. [Unrestricted access to quiesce functionality in dss.api.playstation.com REST API leads to unavailability of application](https://hackerone.com/reports/993722) to PlayStation - 39 upvotes, $1000
27. [[stored xss, pornhub.com] stream post function](https://hackerone.com/reports/138075) to Pornhub - 35 upvotes, $1500
28. [Parameter Manipulation allowed for editing the shipping address for other user’s teavana.com subscriptions.](https://hackerone.com/reports/141120) to Starbucks - 33 upvotes, $4000
29. [Logic flaw in the Post creation process allows creating posts with arbitrary types without needing the corresponding nonce](https://hackerone.com/reports/404323) to WordPress - 33 upvotes, $900
30. [SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]](https://hackerone.com/reports/1628209) to U.S. Dept Of Defense - 32 upvotes, $4000
31. [Able to steal private files by manipulating response using Auto Reply function of Lark](https://hackerone.com/reports/1387320) to Lark Technologies - 31 upvotes, $2000
32. [Business Logic Flaw in the subscription of the app](https://hackerone.com/reports/1505189) to Kraden - 31 upvotes, $250
33. [Price manipulation via fraction values (Parameter Tampering)](https://hackerone.com/reports/388564) to Shipt - 31 upvotes, $100
34. [Privilege escalation allows to use iframe functionality w/o upgrade](https://hackerone.com/reports/594080) to Infogram - 31 upvotes, $0
35. [Week Passwords generated by password reset function](https://hackerone.com/reports/765031) to MTN Group - 30 upvotes, $0
36. [Self-XSS in password reset functionality](https://hackerone.com/reports/286667) to Shopify - 29 upvotes, $500
37. [Parameter tampering can result in product price manipulation](https://hackerone.com/reports/218748) to Adobe - 28 upvotes, $0
38. [Manipulation of exam results at Semrush.Academy](https://hackerone.com/reports/662583) to Semrush - 27 upvotes, $600
39. [RCE via Print function [Simplenote 1.1.3 - Desktop app]](https://hackerone.com/reports/358049) to Automattic - 26 upvotes, $250
40. [GoldSrc: Buffer Overflow in DELTA_ParseDelta function leads to RCE](https://hackerone.com/reports/484745) to Valve - 25 upvotes, $3000
41. [Add more seats by paying less via PUT /v2/seats request manipulation](https://hackerone.com/reports/1446090) to Krisp - 23 upvotes, $500
42. [Business Logic Flaw - A non premium user can change/update retailers to get cashback on all the retailers associated with Curve](https://hackerone.com/reports/672487) to Curve - 19 upvotes, $1000
43. [Notifications sent due to "Transfer report" functionality may be sent to users who are no longer authorized to see the report](https://hackerone.com/reports/442843) to HackerOne - 19 upvotes, $500
44. [IDOR in report download functionality on ads.tiktok.com](https://hackerone.com/reports/1559739) to TikTok - 16 upvotes, $500
45. [Multiple File Manipulation bugs in WP Super Cache](https://hackerone.com/reports/240886) to Automattic - 15 upvotes, $150
46. [Response Manipulation leads to Admin Panel Login Bypass at](https://hackerone.com/reports/1508661) [https://██████/](https://xn--4zhaaaaa/) to Sony - 15 upvotes, $0
47. [XSS in main search, use class tag to imitate Reverb.com core functionality, create false login window](https://hackerone.com/reports/351376) to [Reverb.com](http://reverb.com/) - 14 upvotes, $150
48. [Spoof Email with Hyperlink Injection via Invites functionality](https://hackerone.com/reports/182008) to Pushwoosh - 14 upvotes, $0
49. [Remote Code Execution through Extension Bypass on Log Functionality](https://hackerone.com/reports/841947) to Concrete CMS - 14 upvotes, $0
50. [Privilege escalation in the client impersonation functionality](https://hackerone.com/reports/221454) to Ubiquiti Inc. - 12 upvotes, $1500
51. [CSV-injection in export functionality](https://hackerone.com/reports/335447) to Passit - 12 upvotes, $0
52. [Unauthenticated reflected XSS in preview_as_user function](https://hackerone.com/reports/643442) to Concrete CMS - 12 upvotes, $0
53. [Stored self XSS at auto.mail.ru using add_review functionality](https://hackerone.com/reports/914286) to [Mail.ru](http://mail.ru/) - 11 upvotes, $0
54. [[CVE-2020-27194] Linux kernel: eBPF verifier bug in](https://hackerone.com/reports/1010340) [`or`](https://hackerone.com/reports/1010340) [binary operation tracking function leads to LPE](https://hackerone.com/reports/1010340) to Internet Bug Bounty - 10 upvotes, $750
55. [Logic issue in email change process](https://hackerone.com/reports/265931) to Legal Robot - 10 upvotes, $70
56. [[kb.informatica.com] DOM based XSS in the bindBreadCrumb function](https://hackerone.com/reports/189834) to Informatica - 10 upvotes, $0
57. [Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust standard library](https://hackerone.com/reports/1520931) to Internet Bug Bounty - 9 upvotes, $4000
58. [Reflected XSS by way of jQuery function](https://hackerone.com/reports/141493) to Pornhub - 9 upvotes, $50
59. [No Rate limit on Password Reset Function](https://hackerone.com/reports/280389) to Infogram - 9 upvotes, $0
60. [Business Logic, currency arbitrage - Possibility to pay less than the price in USD](https://hackerone.com/reports/1677155) to PortSwigger Web Security - 9 upvotes, $0
61. [Improperly implemented password recovery link functionality](https://hackerone.com/reports/809) to Phabricator - 8 upvotes, $300
62. [Allow authenticated users can edit, trash,and add new in BuddyPress Emails function](https://hackerone.com/reports/833782) to WordPress - 8 upvotes, $225
63. [Logic issue in email change process](https://hackerone.com/reports/266017) to Legal Robot - 8 upvotes, $60
64. [CSRF in the "Add restaurant picture" function](https://hackerone.com/reports/169699) to Zomato - 8 upvotes, $50
65. [Change password logic inversion](https://hackerone.com/reports/255679) to Legal Robot - 8 upvotes, $20
66. [Impersonation of Wakatime user using Invitation functionality.](https://hackerone.com/reports/257119) to WakaTime - 8 upvotes, $0
67. [Server Side Request Forgery In Video to GIF Functionality](https://hackerone.com/reports/91816) to Imgur - 7 upvotes, $1600
68. [memory corruption in wordwrap function](https://hackerone.com/reports/167910) to Internet Bug Bounty - 7 upvotes, $500
69. [Logic flaw enables restricted account to access account license key](https://hackerone.com/reports/200576) to New Relic - 7 upvotes, $500
70. [unchecked unserialize usage in WordPress-Functionality-Plugin-Skeleton/functionality-plugin-skeleton.php](https://hackerone.com/reports/185907) to Ian Dunn - 7 upvotes, $25
71. [Reputation Manipulation (Theoretical)](https://hackerone.com/reports/132057) to HackerOne - 7 upvotes, $0
72. [Business logic Failure - Browser cache management and logout vulnerability in Certly](https://hackerone.com/reports/158270) to Certly - 7 upvotes, $0
73. [Firefly's verify_access_token() function does a byte-by-byte comparison of HMAC values.](https://hackerone.com/reports/240958) to Yelp - 7 upvotes, $0
74. [Missing Password Confirmation at a Critical Function (Payout Method)](https://hackerone.com/reports/303299) to HackerOne - 7 upvotes, $0
75. [Remote Code Execution in the Import Channel function](https://hackerone.com/reports/236607) to ExpressionEngine - 7 upvotes, $0
76. [Deleted Post and Administrative Function Access in eCommerce Forum](https://hackerone.com/reports/167846) to Shopify - 6 upvotes, $500
77. [CSV export/import functionality allows administrators to modify member and message content of a workspace](https://hackerone.com/reports/1661310) to Slack - 6 upvotes, $250
78. [Application XSS filter function Bypass may allow Multiple stored XSS](https://hackerone.com/reports/44217) to Vimeo - 6 upvotes, $100
79. [Non-functional 2FA recovery codes](https://hackerone.com/reports/249337) to Legal Robot - 6 upvotes, $60
80. [Incorrect Functionality of Password reset links](https://hackerone.com/reports/280529) to Infogram - 6 upvotes, $0
81. [Business Logic Flaw allowing Privilege Escalation](https://hackerone.com/reports/280914) to Inflection - 6 upvotes, $0
82. [Parameter tampering : Price Manipulation of Products](https://hackerone.com/reports/682344) to WordPress - 6 upvotes, $0
83. [Lodash "difference" (possibly others) Function Denial of Service Through Unvalidated Input](https://hackerone.com/reports/670779) to Node.js third-party modules - 6 upvotes, $0
84. [Owner can change themself for another Role Mode but application doesnot have this function.](https://hackerone.com/reports/1072635) to Doppler - 6 upvotes, $0
85. [ihsinme: CPP Add query for CWE-783 Operator Precedence Logic Error When Use Bool Type](https://hackerone.com/reports/1241578) to GitHub Security Lab - 5 upvotes, $1800
86. [Logic Issue with Reputation: Boost Reputation Points](https://hackerone.com/reports/36211) to HackerOne - 5 upvotes, $500
87. [The PdfServlet-functionality used by the "Tee vakuutustodistus" allows injection of custom PDF-content via CSRF-attack](https://hackerone.com/reports/129002) to LocalTapiola - 5 upvotes, $300
88. [Deleted name still present via mouseover functionality for user accounts](https://hackerone.com/reports/127914) to HackerOne - 5 upvotes, $0
89. [Issue with password reset functionality [Minor]](https://hackerone.com/reports/149027) to Paragon Initiative Enterprises - 5 upvotes, $0
90. [Weak e-mail change functionality could lead to account takeover](https://hackerone.com/reports/223461) to Weblate - 5 upvotes, $0
91. [Amount Manipulation Buy Unlimited Credits in just $1.00](https://hackerone.com/reports/277377) to Inflection - 5 upvotes, $0
92. [Locked_Transfer functional burning](https://hackerone.com/reports/417515) to Monero - 5 upvotes, $0
93. [Rate limit function bypass can leads to occur huge critical problem into website.](https://hackerone.com/reports/1067533) to Courier - 5 upvotes, $0
94. [HTTP Host injection in redirect_to function](https://hackerone.com/reports/888176) to Ruby on Rails - 5 upvotes, $0
95. [2 Cache Poisoning Attack Methods Affect Core Functionality www.exodus.com](https://hackerone.com/reports/1581454) to Exodus - 5 upvotes, $0
96. [Manipulation of submit payment request allows me to obtain Infrastructure Pro/Other Services for free or at greatly reduced price](https://hackerone.com/reports/219356) to New Relic - 4 upvotes, $600
97. [Invalid parameter in memcpy function trough openssl_pbkdf2](https://hackerone.com/reports/190933) to Internet Bug Bounty - 4 upvotes, $500
98. [Business logic Failure - Browser cache management and logout vulnerability.](https://hackerone.com/reports/7909) to Localize - 4 upvotes, $0
99. [Spamming any user from Reset Password Function](https://hackerone.com/reports/223525) to Weblate - 4 upvotes, $0
100. [New team invitation functionality allows extend team without upgrade](https://hackerone.com/reports/295900) to Infogram - 4 upvotes, $0