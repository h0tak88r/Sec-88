# Profile - Settings

**Change Password Feature**

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

## Social Media Links

* [ ] &#x20;Unsafe handle of social media links on profile&#x20;

{% embed url="https://hackerone.com/reports/2483422" %}

* [ ] Change Username to Restricted PATH to Bypass Access Control to IDOR&#x20;

{% embed url="https://x.com/Mohnad/status/1886451919276679282?t=ykPDjfv7FfYLmDAzAhBuxA&s=09" %}

