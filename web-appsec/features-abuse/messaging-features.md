# Messaging Features



* [ ] Blind XSS/HTML Injection
*   [ ] Markup Language? try [**Create A picture that steals Data**](https://medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba1012)

    ```python
    Go to <https://iplogger.org/>
    choose invisible image 
    send the message 
    ```
* [ ] XSS HTML Injection in email section
* [ ] Change message ID in request → access other users’ messages
* [ ] Change conversation/thread ID → view other conversations
* [ ] Access messages after logout
* [ ] Access deleted/archived messages via direct endpoint
* [ ] Reply to a thread you shouldn’t have access to
* [ ] Modify user/client ID in requests
* [ ] Client accessing firm staff messages
* [ ] Staff accessing unauthorized threads
* [ ] Reuse old session token after logout
* [ ] Check for data leakage across accounts
* [ ] Access APIs without authentication
* [ ] Inject in message body
* [ ] Inject in subject/title
* [ ] Inject in reply field
* [ ] Test payloads:

```html
tester'\"/><<h1>h1>ester0x88<</h1>/h1>
0x88"><<img/src=https://tinyurl.com/ynaeed3d>img/src=https://tinyurl.com/ynaeed3d>
Your Account has been suspended you should change your password From Here <a/href=https://evil.com>change password</a
```

* [ ] SVG payloads
* [ ] HTML-encoded payloads
* [ ] Check execution in:
  * [ ] Web UI
  * [ ] Email notifications
* [ ] Email contains full message content
* [ ] Email leaks sensitive data
* [ ] HTML injection in email rendering
* [ ] Email header injection (\n, %0a)
* [ ] Trigger multiple notifications (spam)
* [ ] Email exposes internal IDs or hidden fields
* [ ] Upload .html files
* [ ] Upload .svg files
* [ ] Upload .js files
* [ ] Upload PDF with embedded JS
* [ ] Double extensions (file.jpg.html)
* [ ] Bypass Content-Type validation
* [ ] Inject payload in filename
* [ ] Access uploaded files via direct URL
* [ ] Access other users’ attachments (IDOR)
* [ ] Modify sender ID
* [ ] Modify recipient ID
* [ ] Send message as another user
* [ ] Replay request (duplicate messages)
* [ ] Modify message content after sending
* [ ] Send message when messaging is disabled
* [ ] Send message when user is blocked
* [ ] Secure messaging leaks via email
* [ ] Bypass client/staff messaging restrictions
* [ ] Inspect API responses for hidden fields
* [ ] Leak email addresses or internal IDs
* [ ] Trigger errors → check for stack traces
* [ ] Message metadata leakage
* [ ] Send high volume of messages quickly
* [ ] Check rate limiting
* [ ] Email bombing via notifications
* [ ] Large payloads (DoS potential)
* [ ] Send message without CSRF token
* [ ] Build CSRF PoC (auto-send message)
* [ ] Check SameSite cookie protection
* [ ] Very long messages (10k+ chars)
* [ ] Unicode / RTL text
* [ ] Emojis
* [ ] Null byte injection (%00)
* [ ] Broken JSON / missing parameters
* [ ] IDOR on messages/conversations
* [ ] Stored XSS (UI + email)
* [ ] Attachment access bypass
* [ ] Email data leakage
* [ ] Sender/recipient tampering
