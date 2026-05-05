# Inviting Feature



<details>

<summary><strong>Links</strong></summary>

* ​https://x.com/0x\_rood/status/1749057124817100862
* https://medium.com/@mrxdevil404/some-cases-bugs-on-invitation-bug-to-higher-impact-fd3f7268d469​
* ​https://x.com/0x\_rood/status/1727329838149644473
* https://x.com/0x\_rood/status/1749501798593798578
* https://x.com/0x\_rood/status/1727322288163258694​

</details>

<details>

<summary><strong>Methodology</strong></summary>



</details>

<details>

<summary><strong>Token Leaked In Response</strong></summary>

* [ ] Token Leaked in the `Resend-Token` endpoint

</details>

<details>

<summary><strong>Failure to invalidate token</strong></summary>

1. Invitation link doesn't expire
2. Generate an invitation link and send it to your secondary account to join the team.
3. Accept the invitation.
4. Remove the secondary user from the team.
5. Try to rejoin the organization using the same invitation link, and prepare to be amazed!

</details>

<details>

<summary><strong>Second admin can deactive 2FA for first admin without password</strong></summary>

1. Admin need to put password to deactive 2FA
2. Admin can invite another admin
3. Second admin can deactive 2FA for first admin without password

</details>

<details>

<summary><strong>IDOR in email parameter when sign up using invitation feature</strong></summary>

1. Admin invite user with specific email
2. User open message in email to complete registertion
3. After finish user intercept request before submit
4. Change email at email parameter
5. Email changed Successfully

</details>

<details>

<summary><strong>API Misconfiguration Leads to PrevEsc</strong> </summary>

1. Admin invite user
2. User login
3. In user login request there's parameter called role:"user"
4. Use match & replace to changed it to role:"admin"
5. Login with user, it's logout me directly
6. But i see all informtion with burp via api endpoints

</details>

<details>

<summary><strong>Signup without accept invitation</strong></summary>

1. Send invite to [test@example.com](mailto:test@example.com)
2. Disregard Invite, directly signup.
3. [test@example.com](mailto:test@example.com) becomes part of the organisation.
4. Victim organisation dashboard still shows that [test@example.com](mailto:test@example.com) hasn’t accepted the invitation sent to email.
5. But in real time [test@example.com](mailto:test@example.com) remains part of the organisation anonymously.

</details>

<details>

<summary><strong>Logic Error Leads to Project Takeover</strong></summary>

1. User invite attacker to the project as member
2. Attacker changes his name with bad chracters like html tags and %00 and other latina chars
3. Victim tries to remove attacker from the team but he faces errors and the request doesn't occure

</details>

<details>

<summary><strong>Injection</strong></summary>

* [ ] XSS in first-name through invitaiton link

</details>

<details>

<summary><strong>BAC</strong></summary>

{% hint style="info" %}
**Methodology:** just pass the jwt and cookie of the low leverage user to auth analyzer and it will repeat all admin requests with the lower privilege user
{% endhint %}

* [ ] Member invite admin
* [ ] Viewer edit content
* [ ] Member invite member
* [ ] Member edit org settings
* [ ] Member can remove members
* [ ] Viewer can edit
* [ ] Member edit permissions



</details>

<details>

<summary><strong>Sign_up without accepting the invitation the attacker join organization anonymously</strong></summary>



</details>

<details>

<summary><strong>Race Condition</strong></summary>

* [ ] Race Condition in invite user
* [ ] Race Condition in accepting invitation

</details>
