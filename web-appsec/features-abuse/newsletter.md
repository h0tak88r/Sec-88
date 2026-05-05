# Newsletter

<details>

<summary><strong>IDOR</strong></summary>

* [ ] Changing the newsletter ID

</details>

<details>

<summary><strong>Excessive Data Exposure</strong></summary>

* [ ] Sometimes Server Leaks A lot of information in response

</details>

<details>

<summary><strong>CSRF</strong> </summary>

* [ ] Subscribe/unsubscribe option

</details>

<details>

<summary><strong>Injection</strong></summary>

* [ ] SQL Injection in email parameter or other parameters
* [ ] XSS/HTML Injection

`https://testbuguser.myshopify.com/?contact[email]%20onfocus%3djavascript:alert(%27xss%27)%20autofocus%20a=a&form_type[a]aaa`&#x20;

</details>

<details>

<summary><strong>Unverified User Can Post Newsletter</strong></summary>

{% embed url="https://hackerone.com/reports/1691603" %}

1. Sign up for an account on Linkedin
2. Without verifying the email, jump directly to the URL : `https://www.linkedin.com/post/new/` to write an article&#x20;
3. It can be seen that there is no option to create a Newsletter.
4. Now Login into the account where the Email is verified and try to create a newsletter.
5. Click on Done and capture the vulnerable request and replay the request with the unverified user cookies. and the newsletter will be successfully created.

</details>

<details>

<summary><strong>BAC by Filling the form with other's email</strong></summary>

{% embed url="https://hackerone.com/reports/145396" %}

The mentioned URL contains a form that, when supplied correct user emails, unsubscribes users from the newsletters they're subscribed to. If the user is not subscribed, the form returns a message that says that the user is not subscribed if this is the case.

</details>

<details>

<summary><strong>No Rate Limit</strong></summary>

{% embed url="https://hackerone.com/reports/145612" %}

> The lack of a captcah or verificationcodeX (it's empty) in your phplist configuration allows attackers to use this mail for to send as much spam as they like to victims. I did not reach an email sending limit when I had tested this.



* [ ] No Captcha or Rate Limit Leads to Email Spam

</details>

<details>

<summary><strong>Host header injection/redirection via newsletter signup</strong></summary>

{% embed url="https://hackerone.com/reports/229498" %}

> There's a host header injection vulnerability via all newsletter signups in the referrer attribute. This works with all pages that have "Join our email list" signup boxes.
>
> **Since the referrer attribute can be changed to an outside domain the email being received redirects all links within the "Welcome to Starbucks" email. So in result the member is redirected to a malicious site from the email they used.**

</details>
