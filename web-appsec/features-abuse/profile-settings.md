# Profile - Settings

## **Change Password Feature**

*   [ ] [Missing rate limit in current password](https://hackerone.com/reports/1170522)

    ```python
    Steps To Reproduce:
    Login to <https://reddit.com/>
    Navigate to user settings > Change password
    Enter incorrect password in old password field and enter a new matching passwords in other two fields
    Turn on your burpsuite proxy and click save
    You'll notice the error as Incorrect password
    send the request <https://www.reddit.com/change_password> to your burpsuite intruder to bruteforce
    Add the payload to the current_password parameter
    select list of passwords for like 100 lines and start attack
    ```
* [ ] [password change is confirmed when not matching](https://hackerone.com/reports/803028)
* [ ] CSRF \[\[CSRF]]
* [ ] [CSRF bug on password change](https://hackerone.com/reports/230436)
*   [ ] Misconfiguration in Change-password Functionality

    ```python
    Attack Workflow:

    1. Change the email to the victim email.

    2. Remove [The Header (X_auth_credentials) and the Parameter (‘currentPassword ‘)].

    3. Put any new password you want

    4. Send the request and you got 200 OK as a response.

    5. Login to the victim account with the new password and here we go you successfully accessed his account.

    https://0x2m.medium.com/misconfiguration-in-change-password-functionality-leads-to-account-takeover-1314b5507abf
    ```
* [ ] [User Account Takeover](https://rohitcoder.medium.com/user-account-takeover-password-change-nice-catch-2293f4d272b2)
* [ ] [Abused 2FA to maintain persistence after a password change](https://medium.com/@lukeberner/how-i-abused-2fa-to-maintain-persistence-after-a-password-change-google-microsoft-instagram-7e3f455b71a1)
* [ ] [old session dose not expire after password change](https://hackerone.com/reports/1166076)
* [ ] Response Manipulation

> **Change Name Feature**

* [ ] `test.com/user/tester` —> Try Path Overwrite -> `test.com/user/login.php`
* [ ] [XSS via Account Name](https://hackerone.com/reports/34725)
* [ ] [ATO PII chained with stored XSS](https://hackerone.com/reports/1483201)
*   [ ] self XSS to Open Redirect

    ```jsx
    I decided to check the site's login (which contains registration through Google)
    I found that you can register with any email without verification
    Here I registered my email associated with Google without verifying the email and put the payload, but here I did not need to steal his cookie so I used
    			<meta http-equiv="Refresh"content="5;url=evil.com">
    I logged into my account via Google
    Once I enter the settings, it directs me to another site
    Thus, you can prevent any user from registering for an account and adjusting the name
    ```
*   [ ] Request manipulation to change user name leads to email change

    ```jsx
    Prevent people from registering with a Google account
    In the beginning, I created an account on the site test.com
     (the site contains a login feature from Google)
    -------------------------------------------
    1. I went to the settings and found the site does not allow changing the email with which you created the account with
    2. I decided to take the request for changing the name and added a parameter called "<email:test@gmail.com>"
    3. You can enter any person's email without authentication
    4. The account email has been changed to the email written above
    5. I logged in again to the site, but from a second browser via Google (test@gmail.com), I was rejected, and I got a Forbidden access
    6. I tried to reset the password I was banned from entering my account permanently.
    --------------------------------------------------------------------------
    ```

## **Change Email Feature**

* [ ] [Unlocking Important Resources with Email Verification Bypass](https://twitter.com/Jayesh25\_/status/1725429962931335599)

```
Identify critical features linked to a user's email domain. For instance, consider a target app that grants access to resources based on your email domain. Some apps let you join a team or workspace directly if your email matches the team's domain (e.g., join Victim SITE XYZ only with sample@victimsitexyz[.]com). Others restrict access to documents or videos based on email domain whitelisting. Numerous such opportunities exist where email plays a crucial role.

1️. Log in to your attacker account and change your email address to an attacker-controlled email (e.g., attackeremail@attackerdomain.com). 

2️. You'll likely receive an email confirmation link on your attacker-controlled email (Do not verify it yet). 

3️. Now, change your email to the unregistered email or domain you wish to HIJACK (e.g., victimemail@victimdomain.com). 

4️. This action will send an email verification link to victimemail@victimdomain.com, which you don't have access to. 

5️. Try clicking on the "Email" verification link sent earlier to attackeremail@attackerdomain.com. If the system fails to revoke the previous email verification link, the link for attackeremail@attackerdomain.com could end up verifying the email for victimemail@victimdomain.com, allowing you to claim it as verified.

Once you've claimed an email associated with another organization's domain, identify the associated functions to prove impact and report it to earn some generous bounties
```

* [ ] Binding an email using a confirmation link Try to follow a confirmation link for account `A` within the session of account `B` within an email confirmation flow. If an application is vulnerable, it will link the verified email to account `B`. In this case, the attack flow may look like:
  1. An attacker links `attacker@website.com` to their account.
  2. An attacker sends a confirmation link to a victim.
  3. A victim follows the link from an email while logged into an application.
  4. An application links `attacker@website.com` to a victim. References:
  5. [Writeup: Watch out the links : Account takeover!](https://akashhamal0x01.medium.com/watch-out-the-links-account-takeover-32b9315390a7)
* [ ] Lack of password confirmation when email change [No Password Verification on Changing Email Address Cause ATO](https://hackerone.com/reports/292673)
*   [ ] [Insufficient Session Expiration - Previously issued email change tokens do not expire upon issuing a new email change token'](https://hackerone.com/reports/1006677)

    * The email verification code was not expired when a new one was generated.
    * So suppose we are [victim@gmail.com](mailto:victim@gmail.com) , now login into the website then
    * go to account settings and change mail address to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com)
    * a link will be sent to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com), now the user realizes that he have lost access to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com) due to some reasons
    * so he will probably change mail to the another mail address for e.g [victim3@gmail.com](mailto:victim999@gmail.com) which he owns and has access to
    * but it is found that even after verifying victim3@gmail.com, the old link which was sent to victim2@gmail.com is active, so user/attacker having access to that mail can verify it and Observe the OAuth misconfiguration that leads to account takeover

    > [Full Account takeover due to OAuth misconfiguration | by Cysky0x1 | Sep, 2023 | Medium](https://medium.com/@cysky9/full-account-takeover-due-to-oauth-misconfiguration-50d8747b268e)
* [ ] email confirmation misconfiguration
  1. request to change the email to `test@x.y`
  2. you will receive a confirmation link
  3. don't confirm and go register account
  4. then use email changing confirmation link
* [ ] ATO by changing the email to existing account
* [ ] Try \[\[XSS\_HTML Injection|XSS\_HTML Injection]] in email Section
* [ ] Improper Session Management Leads to ATO
  1. evil@a.com changes mail to 2@gmail.com (owned) -> gets email verification link
  2. sends link to victim, victim opens and victims account email is updated
  3. when someone says its phishing! u know u can convert it to csrf ;), auto submit GET request lol! that makes more sense!
  4. [Watch out the links : Account takeover! | by Akash Hamal | Medium](https://akashhamal0x01.medium.com/watch-out-the-links-account-takeover-32b9315390a7)
* [ ] **Confirmation link not expired + OAUTH misconfiguration = ATO**
  1. go to account settings and change mail address to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com)
  2. a link will be sent to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com), now the user realizes that he have lost access to [victim](mailto:victim@gmail.com)2[@gmail.com](mailto:victim111@gmail.com) due to some reasons
  3. so he will probably change mail to the another mail address for e.g [victim3@gmail.com](mailto:victim999@gmail.com) which he owns and has access to
  4. but it is found that even after verifying victim3@gmail.com, the old link which was sent to victim2@gmail.com is active, so user/attacker having access to that mail can verify it and Observe the OAuth misconfiguration that leads to account takeover
* [ ] [Ability To Takeover any account by Emaill.](https://hackerone.com/reports/240821)

## **Change Numbers Feature**

*   [ ] Bypass Disallowed Change Phone Number Feature

    ```jsx
    When I created the account, I faced a function of 3 steps
    1. Upload Profile Picture
    2. Set Username
    3. Set Phone Number
    and the Phone number in my profile later is not allowed to change it
    No "Change Button" Around it here as we can see !!
    So What do you think i did?
    Quickly, I ran into my burp requests history !!
    and I Inspected the full function of adding phone number !!
    Since the website is using "GraphQL" so the steps of adding phone number was containing 2 OperationNames
    1. Adding: SetPhoneNumber
    2. Verifying: VerifyPhoneNumber
    -----------------------------------------------------------------------------------------
    By Changing the phone number in the first operation name, which is: SetPhoneNumber
    I received a 200 OK With a valid response!!
    & I received a verification code on the new number I added!!!
    -------------------------------------------------------------------------------
    Then sent the code that I've received in the second OperationName, which was: VerifyPhoneNumber
    and It worked fine!! Totally fine!!
    Valid Response and the phone number changed now <3
    ```

## **Account Delete Feature**

* [ ] [**Lack of Password Confirmation for Account Deletion**](https://hackerone.com/reports/950471)
* [ ] \[CSRF to delete accounts]\(https://hackerone.com/reports/1629828 ")
* [ ] \[\[IDOR|IDOR]] in Account Deletion Process

## **Other**

*   IDOR To ATO

    ```jsx
    1- We create an account
    2- Then we log in
    3- go to edit profile
    4- We open burp suite
    5- Then we intercepted to the request to save the modification
    6- We’re gonna change the email to the victim’s email And Enter a new password Through the burpsuite
    7- Then we send the request to the intruder
    8- Now we’re gonna guess the victim’s (user_idx)
    9- We will guess the user_idx
    10- We will guess the user_idx from 1 to 2500
    11- Another note I noticed when accepting the request will be in the response (“result”:1)and when not accepting it will be (“result”:-1)
    12- Therefore, before turning on the intruder, we search for “result”: 1 by Grep in options
    13- Then we turn on the intruder
    14- We will notice after completion, find the user_idx of the victim , and the new password has already been set for this account and therefore we can log in with the email and the new password that we created
    ```
*   Browser Cache

    ```python
    1- Check the response server when sending a request to sure from cache operation.
    2- Send The request to Intruder and send 50 requests.
    3- When you reload the page multiple times, it gives you random data related to multiple users.
    ```

## **Logout Feature**

* [ ] [**CSRF with logout action**](https://hackerone.com/reports/1971589)
*   [ ] **Failure to Invalidate Session On Logout**

    ```bash
    1) log in to the application using Chrome Browser and browse the application
    2) Use “Edit this Cookie” plugin in Chrome and copy all the cookies present
    3) Now Logout of the application and Clear the cookies from browser
    4) Use “Edit this Cookie” plugin and paste all the cookies that copied earlier
    5) Click on Okay and refresh the page, can see the application is getting logged in
    --------------------
    Login into your wakatime.com account.
    Capture any request. For example Account Settings using Burp Proxy.
    Logout from the website.
    Replay the request captured in step 2 and notice it displays the proper response
    -------------------------------------------------------
    <https://hackerone.com/reports/244875>
    <https://zofixer.com/what-is-failure-to-invalidate-session-on-logout-client-and-server-side-vulnerability/>
    <https://hackerone.com/reports/634488>
    ```

## **Account Linking**

*   ATO Via Response Manipulation

    ```json
    STEPS TO REPRODUCE
    1. Open a browser in which a user has previously logged into an account, but hasn't logged out.
    2. Open another browser and login using your account
    3. Try to link gmail using your account, it will prompt for a password confirmation, enter your password
    4. Intercept the response and copy it
    5. Go to the victims account and link to gmail again
    6. This time enter any password and intercept response
    7. Paste the copied response from the attacker account

    # References
    - <https://hackerone.com/reports/1040373>
    ```
