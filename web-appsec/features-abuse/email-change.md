# Email Change

<details>

<summary><strong>Domain-Based Authorization Hijacking</strong></summary>

> Identify critical features linked to a user's email domain. For instance, consider a target app that grants access to resources based on your email domain. Some apps let you join a team or workspace directly if your email matches the team's domain (e.g., join Victim SITE XYZ only with sample@victimsitexyz\[.]com). Others restrict access to documents or videos based on email domain whitelisting. Numerous such opportunities exist where email plays a crucial role.

[Unlocking Important Resources with Email Verification Bypass ](https://x.com/Jayesh25/status/1725429962931335599)

1. Log in to your attacker account and change your email address to an attacker-controlled email (e.g., attackeremail@attackerdomain.com).&#x20;
2. You'll likely receive an email confirmation link on your attacker-controlled email (Do not verify it yet).

* Now, change your email to the unregistered email or domain you wish to HIJACK (e.g., victimemail@victimdomain.com).
* This action will send an email verification link to victimemail@victimdomain.com, which you don't have access to.
* Try clicking on the "Email" verification link sent earlier to attackeremail@attackerdomain.com. If the system fails to revoke the previous email verification link,
* the link for attackeremail@attackerdomain.com could end up verifying the email for victimemail@victimdomain.com, allowing you to claim it as verified.

1. Once you've claimed an email associated with another organization's domain, identify the associated functions to prove impact and report it to earn some generous bounties

</details>

<details>

<summary><strong>Improper Integrity Leads to ATO</strong></summary>

{% embed url="https://akashhamal0x01.medium.com/watch-out-the-links-account-takeover-32b9315390a7" %}

1. An attacker links `attacker@website.com` to their account.
2. An attacker sends a email-change confirmation link to a victim.
3. A victim follows the link from an email while logged into an application.
4. An application links `attacker@website.com` to a victim.

</details>

<details>

<summary><strong>Improper Session Validation</strong></summary>

* [ ] [Insufficient Session Expiration - Previously issued email change tokens do not expire upon issuing a new email change token](https://hackerone.com/reports/1006677)
* [ ] [user changes mail to attacker@gmail.com -> user realizes that he mistyped the mail -> so he again changes to mail he owns and verifies it -> old link sent to attacker@gmail.com is still active even after new mail has been verified](https://cysky0x1.medium.com/full-account-takeover-due-to-oauth-misconfiguration-50d8747b268e)

</details>

<details>

<summary><strong>Misconfiguration Between Email Change and Registration Features</strong></summary>

1. Request to change the email to `test@x.y`
2. You will receive a confirmation link
3. Don't confirm and go register account
4. Then use email changing confirmation link

</details>

<details>

<summary><strong>ATO by changing the email to existing account</strong></summary>

* [ ] IDN Homograph Attack
* [ ] Bypassing “email already exists” error By `NULL Byte Attack` and `Special Characters %20` at the end `your@email.com%20`

</details>

<details>

<summary><strong>Email-Change Confirmation Workflow and</strong> <strong>OAUTH misconfiguration</strong> </summary>

1. Go to account settings and change mail address to victim2@gmail.com
2. Link will be sent to victim2@gmail.com, now the user realizes that he have lost access to victim2@gmail.com due to some reasons
3. Change mail to the another mail address for e.g victim3@gmail.com which he owns and has access to
4. Even after verifying victim3@gmail.com, the old link which was sent to victim2@gmail.com is active, so user/attacker having access to that mail can verify it and Observe the OAuth misconfiguration that leads to account takeover

</details>

<details>

<summary><strong>XSS/HTML Injection</strong></summary>

* [ ] Test XSS in email Section
* [ ] Test Html Injection Reflected in Victim EMail after changing your email to his email

</details>

*
* [ ] Lack of password confirmation when email change [No Password Verification on Changing Email Address Cause ATO](https://hackerone.com/reports/292673)
*

