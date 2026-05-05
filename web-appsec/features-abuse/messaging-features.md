# Messaging Features



<details>

<summary><strong>Injection</strong></summary>

* [ ] Blind XSS/HTML Injection
* [ ] HTML injection in email rendering
* [ ] XSS HTML Injection in email section
* [ ] Inject in message body
* [ ] Inject in subject/title
* [ ] Inject in reply field
* [ ] Email header injection (`\n`, `%0a`)

```html
tester'\"/><<h1>h1>ester0x88<</h1>/h1>
0x88"><<img/src=https://tinyurl.com/ynaeed3d>img/src=https://tinyurl.com/ynaeed3d>
Your Account has been suspended you should change your password From Here <a/href=https://evil.com>change password</a
```

* [ ] Check execution in:
  * [ ] Web UI
  * [ ] Email notifications

</details>

<details>

<summary><strong>Markup Injection</strong></summary>

{% embed url="https://medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba1012" %}

1. Go to [https://iplogger.org/](https://iplogger.org/)
2. Choose invisible&#x20;
3. Image send the message

</details>

<details>

<summary><strong>IDOR</strong></summary>

* [ ] Change message ID in request → access other users’ messages
* [ ] Change conversation/thread ID → view other conversations
* [ ] Modify user/client ID in requests
* [ ] Send message as another user
* [ ] Modify recipient ID

</details>

<details>

<summary><strong>Improper Session Validation After Logout</strong></summary>

* [ ] Access messages after logout
* [ ] Reuse old session token after logout

</details>

<details>

<summary><strong>Privilege Escalation</strong></summary>

* [ ] Reply to a thread you shouldn’t have access to
* [ ] Access deleted/archived messages via direct endpoint
* [ ] Client accessing firm staff messages
* [ ] Staff accessing unauthorized threads

</details>

<details>

<summary><strong>Data Leakage in API Responses</strong></summary>

* [ ] Inspect API responses for hidden fields
* [ ] Leak email addresses or internal IDs
* [ ] Check for data leakage across accounts
* [ ] Trigger errors → check for stack traces
* [ ] Message metadata leakage

</details>

<details>

<summary><strong>Unauthenticated Access to APIs</strong></summary>

* [ ] Access APIs without authentication

</details>

<details>

<summary><strong>File Upload Issues</strong></summary>

* [ ] Upload `.html` files
* [ ] Upload `.svg` files
* [ ] Upload `.js` files
* [ ] Upload `PDF` with embedded `JS`
* [ ] Double extensions (`file.jpg.html`)
* [ ] Bypass `Content-Type` validation
* [ ] Inject payload in filename
* [ ] Access uploaded files via direct URL&#x20;
* [ ] Modify sender ID
* [ ] Access other users’ attachments (IDOR)

</details>

<details>

<summary><strong>Leaked Sensitive Information in Email Notifications</strong></summary>

* [ ] Email contains full message content
* [ ] Email leaks sensitive data like emails
* [ ] Email exposes internal IDs or hidden fields
* [ ] Secure messaging leaks via email

</details>

<details>

<summary><strong>Rate Limit Issues</strong></summary>

* [ ] Check rate limiting
* [ ] Trigger multiple notifications (spam)
* [ ] Race Condition
* [ ] Send high volume of messages quickly
* [ ] Email bombing via notifications
* [ ] Very long messages (10k+ chars) -> `DoS Potential`

</details>

<details>

<summary><strong>BAC</strong></summary>

* [ ] Replay request (duplicate messages)
* [ ] Modify message content after sending
* [ ] Send message when messaging is disabled
* [ ] Send message when user is blocked
* [ ] Bypass client/staff messaging restrictions

</details>

<details>

<summary><strong>CSRF</strong></summary>

* [ ] Build CSRF PoC (auto-send message)

</details>

<details>

<summary><strong>Improper Input Validation</strong></summary>

* [ ] Unicode / RTL text
* [ ] Emojis
* [ ] Null byte injection (`%00`)
* [ ] Broken JSON / missing parameters

</details>
