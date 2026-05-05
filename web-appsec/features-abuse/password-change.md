# Password Change

<details>

<summary><strong>Missing rate limit in current password</strong></summary>

{% embed url="https://hackerone.com/reports/1170522" %}

**Steps To Reproduce:**&#x20;

1. Login to [https://reddit.com/](https://reddit.com/)
2. Navigate to user settings > Change password
3. Enter incorrect password in old password field and enter a new matching passwords in other two fields
4. Turn on your burpsuite proxy and click save
5. You'll notice the error as Incorrect password
6. send the request [https://www.reddit.com/change\_password](https://www.reddit.com/change_password) to your burpsuite intruder to bruteforce
7. Add the payload to the `current_password` parameter
8. select list of passwords for like 100 lines and start attack

</details>

<details>

<summary><strong>Password change is confirmed when not matching</strong></summary>

{% embed url="https://hackerone.com/reports/803028" %}

1. Open your wallet.
2. Go to settings.
3. Change wallet password.
4. Enter old password.
5. You now have prompt with two passwords.
6. Enter your new password in the first line.
7. Leaving confirmation blank press enter.
8. Password is changed successfully without confirmation.

</details>

<details>

<summary><strong>CSRF</strong></summary>

{% embed url="https://hackerone.com/reports/230436" %}

[csrf.md](../csrf.md "mention")

</details>

<details>

<summary><strong>Misconfiguration (IDOR)in Change-password Functionality</strong></summary>

**Attack Workflow:**

1. Change the email to the victim email.
2. Remove \[The Header (**X\_auth\_credentials**) and the Parameter (‘**currentPassword** ‘)].
3. Put any new password you want
4. Send the request and you got 200 OK as a response.
5. Login to the victim account with the new password and here we go you successfully accessed his account.

{% embed url="https://0x2m.medium.com/misconfiguration-in-change-password-functionality-leads-to-account-takeover-1314b5507abf" %}

</details>

<details>

<summary><strong>User Account Takeover</strong></summary>

{% embed url="https://rohitcoder.medium.com/user-account-takeover-password-change-nice-catch-2293f4d272b2" %}

### Reproduction steps: <a href="#id-1f76" id="id-1f76"></a>

1. Login into your site.com account.
2. Navigate to [https://www.site.com/users/\[user\_id\]/edit](https://hackerone.com/redirect?signature=b78087cc6960e30f9345e7df07444d659d0d8972\&url=https%3A%2F%2Fwww.thelevelup.com%2Fusers%2F%257BUSER_ID%257D%2Fedit)
3. Now, you will see a form which allows you to edit your account details and there is also another option to change your current password which requires your old password but this can be bypassed easily.
4. Now, for bypassing this change password feature. Just edit your account details and then submit this request and meanwhile intercept it.
5. Now you will notice some **$\_POST** fields which will be like

`user[first_name] // For changing first name`\
`user[last_name] // For changing last name`

</details>

<details>

<summary><strong>Abused 2FA to maintain persistence after a password change</strong></summary>

{% embed url="https://medium.com/@lukeberner/how-i-abused-2fa-to-maintain-persistence-after-a-password-change-google-microsoft-instagram-7e3f455b71a1" %}

* [ ] &#x20;**Step 1: Initiate Login (Attacker)** In Browser A, enter the account's username and current password.
* [ ] **Step 2: Hold at 2FA Prompt (Attacker)** When prompted for the 2FA code, do **not** enter it. Leave this tab open and idle.
* [ ] **Step 3: Simulate Account Recovery (Victim)** In Browser B, log into the account (or use the forgot password flow).
* [ ] **Step 4: Change Password & Disable 2FA (Victim)**\
  Change the account password. This _should_ terminate all active and pending sessions. For maximum impact, completely disable 2FA on the account as well.
* [ ] **Step 5: Test Session Timeout Bypass (Attacker - Optional)**\
  Wait 20-30 minutes. If the 2FA page has a timeout, try to refresh the session token by clicking options like "Try another way" and then re-selecting the 2FA app/SMS method.
* [ ] **Step 6: Execute the Login (Attacker)** Back in Browser A, input a valid 2FA code (generated from the authenticator app or SMS) and hit enter.
* [ ] **Step 7: Verify Impact** Observe if Browser A successfully authenticates and logs into the account. If successful, you have bypassed the password reset and 2FA disablement security controls.

</details>

<details>

<summary><strong>Old session dose not expire after password change</strong></summary>

{% embed url="https://hackerone.com/reports/1166076" %}

**STEPS TO REPRODUCE:**

1. create account in [https://app.upchieve.org/](https://app.upchieve.org/) and login in two browser \[firefox an Chrome]
2. Go to reset password and change it&#x20;
3. You will see that session not expire and account
4. The account is still loged in with old password

</details>

<details>

<summary><strong>Response Manipulation</strong></summary>



</details>
