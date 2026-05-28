# Change Name Feature

<details>

<summary><strong>Path Overwrite</strong></summary>

* [ ] `test.com/user/tester` —> Try Path Overwrite -> `test.com/user/login.php`

</details>

<details>

<summary><strong>Injection Bugs</strong></summary>

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

</details>

<details>

<summary><strong>BOPLA: Broken Object Property Level Authorization</strong></summary>

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

</details>
