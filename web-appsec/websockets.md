# WebSockets

### ⇒ what it is ??

**Cross site web socket hijacking (CSWSH) is similar to CSRF because we utilize the targets cookies to make requests.**

**Also, like CSRF the target would have to visit our malicious page while logged into the target site for this to work.**

**The major difference is instead of sending a POST request we initiate a web socket connection. After the `WebSocket` connection is established we can do whatever want.**

### **⇒ Workflows**

#### live chat feature that uses web sockets for communication

*   [ ] **Examine the traffic in burp** Most people only know how to use burp to test HTTP traffic but it can also handle web socket traffic as shown below:

    ![image](https://user-images.githubusercontent.com/108616378/219940597-7ce3e878-97b7-4867-9048-dbe817633434.png)
* [ ] **Create a POC** to see if we can hijack a user’s `WebSocket` connection | We can use the following website to test for the vulnerability:\[[http://websocket.org/echo.html](http://websocket.org/echo.html) ]
*   [ ] **Manipulating WebSocket messages to exploit vulnerabilities**

    ```jsx
    Click "Live chat" and send a chat message. 
    Itercept the request 
    edit message to <img src=1 onerror='alert(1)'>
    ```
* [ ] [**Manipulating the WebSocket handshake to exploit vulnerabilities**](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)
* [ ] [**Cross-site WebSocket hijacking**](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab)

### Broadcasts Crashes via Manipulating Web-sockets

1. Log in as an admin and assign a moderator to a classroom.
2. As the moderator, intercept the API request for role assignment using tools like Burp Suite or browser developer tools.
3. Modify the request payload as follows:

```
{
    "request_type": "ASSIGN ROLE",
    "payload": {
        "role": "crash",
        "user_id": "55150"
    },
    "request_id": "A1Kptpj0FIfef173-biAa"
}
```

1. Replace the `role` value with a non-standard string such as `crash`.
2. Send the modified request.
3. Observe the effects:

* All live broadcasts in the session will crash.
* Participants will see the error message:

***

### Kick the Session HOST User

1. Moderators intercept WebSocket traffic using tools like browser developer tools or proxies.
2. The **`connection_id`** of the Host is extracted from WebSocket messages.
3. A malicious WebSocket request with the following payload is crafted:

```
{
  "request_type": "KICK",
  "payload": {
    "connection_id": "usr-conn-1ef9c55xu"
  },
  "request_id": "dME5ScO1R4kLK_STnmfUQ"
}
```

4\. The crafted request is sent to the server, resulting in the Host being forcibly removed from the session.

***



\
