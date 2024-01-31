# Registration

## **Throw Way Email Services**

Use throwaway email to create a temporary email: ○[https://mail.protonmail.com](https://mail.protonmail.com) ○[http://en.getairmail.com](http://en.getairmail.com) ○ [https://temp-mail.org/en](https://temp-mail.org/en) ○[https://www.mailinator.com](https://www.mailinator.com)

* [ ] Username/Email Enumeration > Non-Brute Force

```python
Check the Registration Process and try to find Idor or endpoint that leaks usernames/emails
```

* [ ] SQLI in Email Field

```jsx
# SQLI in Email Field

{"email":"asd'a@a.com"} --> Not Valid
{"email":"asd'or'1'='1@a.com" }  --> valid
{"email":"a'-IF(LENGTH(database())>9,SLEE P(7),0)or'1'='1@a.com"} --> Not Valid
{"email":"a'-IF(LENGTH(database())>9,SLEE P(7),0)or'1'='1@a.com"}  -> Valid -->  Delay: 7,854 milis
{"email":"\\"a'-IF(LENGTH(database())=10,SLEEP(7),0)or'1'='1\\"@a.com"} --> {"code":0,"status":200,"mes sage":"Berhasil"} --> Valid --> Delay 8,696 milis
{"email":"\\"a"-IF(LENGTH(database())=11,SLEEP(7),0)or'1'='1\\"@a.com"} ---> {"code":0,"status":200,"mes sage":"Berhasil"} ---> Valid --> No delay

# Resources
- <https://dimazarno.medium.com/bypassing-email-filter-which-leads-to-sql-injection-e57bcbfc6b17>
```

## **Email Verification Feature**

*   [ ] [**Email Verification Bypass Leads to PrivEsc**](https://hackerone.com/reports/791775)

    ```python
    Visit <https://www.shopify.com/pricing> and signup a free trial with an email address, say attacker@gmail.com that you can receive emails
    after entering the fields to enter the store, on top right corner, click your name and go to Your Profile
    change your email to someone that you want to takeover, for example yaworsk@hackerone.com and click save
    All done now, grab a coffee, sit back and relax, watch some YouTube videos and wait for an email to go to your email attacker@gmail.com
    The email that you are waiting for is from mailer@shopify.com, and sent to the old emil
    Click the link and you should see your email has been updated to yaworsk@hackerone.com
    ```
*   [ ] **Email Verification link Doesn't Expire After Email Change Leads to Delete User Account**

    ```jsx
    # Email Verification link Doesn't Expire Leads to Delete User Account

    1. The victim already has an account with the target website, registered with the email address victim@gmail.com.
    2. The attacker attempts to create an account on the target website using their email address, attacker@gmail.com.
    3. The attacker does not proceed with the account creation process and saves the confirmation link without confirming the email.
    4. The attacker presents their Gmail account (attacker@gmail.com) as a gift to the victim.
    5. The victim, believing it to be their own Gmail account, changes the password and assumes control of the Gmail account attacker@gmail.com, which was originally the attacker's account.
    6. The victim decides to change their email address on the target website (recreation).
    7. The victim initiates the email address change process and requests a change email link.
    8. The attacker, having the saved confirmation link, completes the account creation process using the link. Now there is an account with the email address attacker@gmail.com.
    9. Unaware of the attacker's actions, the victim clicks on the update email link and updates their email address to attacker@gmail.com ( Remember! attacker have non access to Gmail account attacker@gmail.com he only have the confirm link)
    10. When the victim attempts to log in, they realize that the newly created account by the attacker in step 8 has overwritten their original account.
    11. The victim tries to recover their account by requesting a password reset, but they can only access the newly created account by the attacker and are unable to regain access to their original account.
    ```
*   [ ] **Email Verification Bypass using OAUTH**

    ```python
    1: Signup for victim@gmail.com using email signup
    2: Signup through google login using the same email
    3: The user will be logged in
    4: This vulnerability is very high severity because of ease of exploitation and complete account access if the victim creates an account.

    <https://hackerone.com/reports/1074047>
    ```
*   [ ] **Verification link leaked in the response**

    ```python
    1: Signup for victim@gmail.com using email signup
    2: check the response for te server

    <https://hackerone.com/hacktivity/cwe_discovery>
    ```
*   [ ] **Bypass via Response Manipulation**

    ```python
    Steps to Reproduce:
    1- First visit your website "<https://hackers.upchieve.org>" and request for the sign up.
    2- In the second step, choose either you want to register as an academic coach or need an academic coach.
    3- In the third step, enter your email and create a password.
    4- In the fourth step, enter name and mobile phone, then sign up.
    5- Then request for verification code on email.
    6- Enter wrong verification code and intercept request using Burp suite.
    7- After intercepting the request, I changed the status from "False" to "True".
    {"status":false to "status":true}
    8- Boom!! Verification code bypassed.
    9- Finally, the account was created with the wrong verification code.

    <https://hackerone.com/reports/1406471>
    ```
* [ ] [**Ability to bypass partner email confirmation to take over any store given an employee email**](https://hackerone.com/reports/300305)
*   [ ] **No Rate Limit when resend Email Confirmation**

    ```python
    try to click resend confirmation email request
    capture it 
    try to send it 50+ times

    <https://hackerone.com/reports/774050>
    ```
*   [ ] **Broken Authentication To Email Verification Bypass**

    ```jsx
    # Broken Authentication To Email Verification Bypass 
    1) First You need to make a account & You will receive a Email verification link. 
    2) Application in my case give less Privileges & Features to access if not verified. 
    3) Logged into the Application & I change the email Address to Email B. 
    4) Verification Link was Send & I verified that. 
    5) Now I again Changed the email back to Email I have entered at the time of account creation. 
    6) It showed me that my Email is Verified. 
    7) Hence , A Succesful Email verfication Bypassed as I haven't Verified the Link which was sent to me in the time of account creation still my email got verified. 
    8) Didn't Receive any code again for verification when I changed back my email & When I open the account it showed in my Profile that its Verified Email.
    ```
* [ ] **ATO from manipulating the email Parameter**

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
```

## **OTP Bypass**

*   [ ] **OTP Bypass Via Response Manipulation**

    ```python
    1.Register 2 accounts with any 2 mobile number(first enter right otp)
      2.Intercept your request
      3.click on action -> Do intercept -> intercept response to this request.
      4.check what the message will display like status:1 or copy the whole response
      5.Follow the same procedure with other account but this time enter wrong otp
      6.Intercept respone to the request
      7.See the message like you get status:0
      8.Change status to 1 i.e, status:1 and forward the request if you logged in means you just done authentication bypass.
    ```
*   [ ] **Bypassing OTP in registration forms by repeating the form submission multiple times using repeater**

    ```python
    1. Create an account with a non-existing phone number
    2. Intercept the Request in BurpSuite
    3. Send the request to the repeater and forward
    4. Go to Repeater tab and change the non-existent phone number to your phone number
    5. If you got an OTP to your phone, try using that OTP to register that non-existent number
    ```
*   [ ] **No Rate Limit When Sending OTP**

    ```python
    1) Create an Account
        2) When Application Ask you For the OTP( One-time password ), Enter wrong OTP and Capture this Request In Burp.
        3) Send This Request into Repeater and repeat it by setting up payload on otp Value.
        4) if there is no Rate Limit then wait for 200 Status Code (Sometimes 302)
        5)if you get 200 ok or 302 Found Status Code that means you've bypass OTP
    ```
*   [ ] **OTP Bypass in JSON**

    ```python
    {
            "code":[
                    "1000",
                    "1001",
                    "1002",
                    "1003",
                    "1004",
                    ...
                    "9999"
                    ]
    }
    ```
*   [ ] **More test cases for bypassing OTP**

    ```python
    1) Check for default OTP - 111111, 123456, 000000
        2) Check if otp has been leaked in respone (Capture the request in burpsuite and send it to repeater to check the response)
        3) Check if old OTP is still vaild
    ```
* [ ] **Duplicate Registration**

```jsx
# Duplicate registration / Overwrite existing user
1. Create first account in application with email say abc@gmail.com and password.
2. Logout of the account and create another account with same email and different password.
3. You can even try to change email case in some case like 
	from abc@gmail.com to Abc@gmail.com
	Try to generate using an existing username
	Check varying the email: uppercase, +1@, Put black characters after the email: test@test.com a , special characters in the email 		 
    name (%00, %09, %20), victim@gmail.com@attacker.com, victim@attacker.com@gmail.com
4. Finish the creation process — and see that it succeeds
5. Now go back and try to login with email and the new password. You are successfully logged in.

Further Read
<https://hackerone.com/reports/187714>
<https://shahjerry33.medium.com/duplicate-registration-the-twinning-twins-883dfee59eaf>
<https://blog.securitybreached.org/2020/01/22/user-account-takeover-via-signup-feature-bug-bounty-poc/>
---------------------------------------------------------------------------------------------------
# Exploit 
# Delete any user account without user interaction The database accepts string as it without convert it to lowercase string
1. Create a normal email ex. theuntest@crowd.com
2. After the email created I able to bypass verify too
3. Bypass for the verify easy, send a valid token to any email the link will be like: <https://the-vulnreable/confi-endpoint/account/confirmemail?userId=maybeeee@gmail.com&token=ananfnasjfasjnfjasfsaa>
4. Just manipulate the email with your email and the email will verified
5. Now login to the normal account as shown I received the JWT normally
6. After create an account customize the email, so the email will be like: MAybeeEE@GmaiL.coM, looks like camel case
7. As shown below I able to register the customized email as an another email
8. After the email created I have the ability to bypass the verify as shown above
9. URL will be like:  <https://the-vulnreable/confi-endpoint/account/confirmemail?userId=MAybeeEE@GmaiL.coM&token=ananfnasjfasjnfjasfsaa>
10. The user will verified
11. Here the two users has signed
12. The user will received authentication successful but will never receives JWT because the customized email will conflicts with the old email in DB
- <https://m.facebook.com/story.php?story_fbid=pfbid0345dp8U87sY32EfSKAnkqsUNJrN9iMt5WLYFZZQHnimriAbgHv2bBQSEPHPV66Sppl&id=100010641453891&mibextid=Nif5oz>
```

* [ ] **DOS at Name/Password field in Signup Page**

```jsx
DOS at Name/Password field in Signup Page.

Steps to reproduce:
1. Go Sign up form.
2. Fill the form and enter a long string in password
3. Click on enter and you’ll get 500 Internal Server error if it is vulnerable.

Further Read
<https://shahjerry33.medium.com/long-string-dos-6ba8ceab3aa0>
<https://hackerone.com/reports/738569>
<https://hackerone.com/reports/223854>
```

* [ ] **PATH Overwrite**

```jsx
# Path Overwrite
If an application allows users to check their profile with direct path /{username} always try to signup with system reserved file names, such as index.php, signup.php, login.php, etc. In some cases what happens here is, when you signup with username: index.php or../../../../index.php , now upon visiting target.tld/index.php, your profile will comeup and occupy the index.php page of an application. Similarly, if an attacker is able to signup with username login.php, Imagine login page getting takeovered.

Further Read: <https://infosecwriteups.com/logical-flaw-resulting-path-hijacking-dd4d1e1e832f>
```

* [ ] **\[\[XSS\_HTML Injection|XSS\_HTML Injection]] in username/email for registration**
* [ ] **No Rate Limit in Registration**
* [ ] **Weak Password Policy**

```jsx
# Weak Password Policy	
check if program accept 
1. weak passwords like 123456
2. username same as email address
3. password same as email address
4. improper implemented password reset and change features
```
