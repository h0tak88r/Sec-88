- [ ] **Manipulating WebSocket messages to exploit vulnerabilities**
- [ ] [**Manipulating the WebSocket handshake to exploit vulnerabilities**](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)
- [ ] [**Cross-site WebSocket hijacking**](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab)

## ⇒ what it is ??

**Cross site web socket hijacking (CSWSH) is similar to CSRF because we utilize the targets cookies to make requests.**

**Also, like CSRF the target would have to visit our malicious page while logged into the target site for this to work.**

**The major difference is instead of sending a POST request we initiate a web socket connection. After the** `**WebSocket**` **connection is established we can do whatever want.**

## **⇒ Workflows**

### live chat feature that uses web sockets for communication

- [ ] **Examine the traffic in burp** Most people only know how to use burp to test HTTP traffic but it can also handle web socket traffic as shown below:
- [ ] **Create a POC** to see if we can hijack a user’s `WebSocket` connection | We can use the following website to test for the vulnerability:[[http://websocket.org/echo.html](http://websocket.org/echo.html) ]