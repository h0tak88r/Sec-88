# Injection Vulnerabilities in GraphQL

### **Introduction**

Injection vulnerabilities occur when an application accepts and processes untrustworthy input without any sanitization. Sanitization is a security measure that involves checking input and removing potentially dangerous characters from it. The absence of such a check could allow the input to be interpreted as a command or a query and execute on either the client side or server side.

### **The Injection Surface**&#x20;

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Network trust boundaries</p></figcaption></figure>

{% embed url="https://owasp.org/API-Security/editions/2023/en/0x11-t10/" %}

GraphQL presents a wide attack surface due to various points where user input can be injected. These include:

* **Query Arguments:** These are parameters supplied to fields in a GraphQL query. The chapter illustrates how the `pastes` field can take a `filter` argument, which can be vulnerable to SQL injection.

```graphql
# Query Inputs
query {
    pastes(limit: 100) {
        id
        ipAddr
    }
}
------------------------------
# Mutation input points
mutation {
    createPaste(content: "Some content", title:"Some title", public: false) {
        paste {
            id
            ipAddr
        }
    }
}
```

**Exploit**

```graphql
# exploit sql injection 
mutation {
    createPaste(content: "content'); DELETE FROM users; --") {
        paste {
            id
            ipAddr
        }
    }
}
```

* **Field Arguments**: GraphQL fields can also accept arguments that can be manipulated. The example provided involves the `username` field, which is shown to accept a `capitalize` argument.

```graphql
query {
    users {
        username(capitalize: true)
        id
    }
}
```

* **Query Directive Arguments:** Directives modify field behavior, and their arguments can also be a point of injection. An example is a `show_network` directive with a `style` argument.

```graphql
query {
    pastes {
        id
        ipAddr @show_network(style: "cidr")
    }
}
```

You can use the introspection query shown in  to get only the available directives by using the `__schema` meta-field with the directives field.

```graphql
query GetDirectives {
    __schema {
        directives {
            name
            description
            locations
        }
    }
}
```

* **Operation Names:** Clients can define operation names, and these can be manipulated to potentially bypass security measures or mislead log analysis. An example involves spoofing the operation name to bypass audit logging, for example using `SpoofedOperationName` instead of `createPaste`.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Executing a selected query based on its operation name in GraphiQL Explorer</p></figcaption></figure>

* **Input Entry Points:** Any place where user-controlled data is input, such as fields in mutations, which are used to create, update, or delete data, can be injection points. The `createPaste` mutation, which uses `content`, `title`, and `public` arguments, is one example.

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* **SQL Injection (SQLi):** The chapter dedicates significant attention to SQL injection, explaining that it can occur when user input is used to construct SQL queries.
  * **Identification:** The chapter advises focusing on fields that accept string values and have names suggesting filtering, such as the `filter` argument in the `pastes` query.
  * **Manual Testing**: Techniques for testing SQL injection manually include using single (') or double (") quotes in input fields to observe how the application responds.
  * **Exploitation:** The chapter explains how to exploit SQLi by using SQL commands, such as `OR 1=1--`, within the filter argument to bypass intended filtering and retrieve all records.
  * **Automated Testing:** The chapter introduces **SQLmap**, a tool for automating SQL injection tests, and explains how to use it to read HTTP requests from a file and test for vulnerabilities.
  * **Database Fingerprinting**: Error messages from the database can be verbose and reveal the database structure to the attacker including table names.
  * **Types of SQL Injection**: The chapter mentions different types of SQLi, such as **blind SQL injection**, **Boolean-based SQL injection**, **error-based SQL injection**, and **time-based SQL injection**.

```graphql
query {
    pastes(filter:"My First Paste'") {
        id
        content
        title
    }
}
----------------------------
query {
    pastes(filter:"My First Paste' or 1=1--") {
        title
        content
    }
}
---------------------------
sqlmap -r request.txt --dbms=sqlite --tables

```

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* **Operating System Command Injection:** The chapter explains how a GraphQL API can be vulnerable to OS command injection, for example when user input is incorporated into system commands.
  * **Code Review:** The chapter highlights the importance of reviewing resolver functions to identify where user inputs are used in OS commands.
  * **Manual Testing**: The chapter demonstrates a manual attack by showing how the `systemDebug` field's `arg` argument can be manipulated to execute commands by using a semicolon to separate them.
  * **Automated Testing:** The chapter introduces **Commix**, a tool that automates OS command injection testing by fuzzing various inputs. It explains how Commix can be used to test variations of payloads, characters, and methods and then save valuable time.

{% code overflow="wrap" %}
```graphql
query {
    systemDebug
}
------------------
query {
    systemDebug(arg:"; uptime")
}
-------------------------
# opuput
PID TTY TIME CMD\n 11999 pts/1 14050 pts/1 1 user, load average: 0.71, 0.84, 0.91\n"\ 00:00:00 bash\n

--------------------
# Automation
commix --url="http://127.0.0.1:5013/graphql" --data='{"query":"query{systemDebug(arg:\"test \")}"}' -p arg
```
{% endcode %}

* **Cross-Site Scripting (XSS):** The chapter discusses how to test for XSS vulnerabilities in GraphQL applications, focusing on three main types of XSS:
  * **Reflected XSS:** The chapter explains that reflected XSS can occur when a malicious script is injected into a request and then reflected back to the user in the response.
  * **Stored XSS:** The chapter notes that stored XSS occurs when malicious code is stored on the server, which can then be executed by other users accessing that data.
  * **DOM-Based XSS:** The chapter explains that DOM-based XSS can be exploited by manipulating the client-side JavaScript.
  * **Testing:** The chapter demonstrates how to test for XSS by inserting JavaScript code, such as `<script>alert("XSS")</script>`, into a mutation’s input fields like the `content` field of `createPaste`, and see if the injected script executes.

```graphql
query {
    hello(msg:"<script>document.cookie;</script>")
}
---------------------------
http://example.com/graphql?query=query%20%7B%0A%20%20hello(msg%3A%22hello%22)%0A%7D
----------------------------
http://example.com/graphql?query=query {hello(msg:"hello")}
```

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption><p>A stored XSS vulnerability impacting adjacent applications</p></figcaption></figure>



* **Importance of Resolver Functions:** The chapter underscores that understanding how resolver functions process client data is important for finding injection points. Reviewing resolver functions can reveal how inputs are handled and whether they are properly sanitized.

```python
def resolve_system_debug(self, info, arg=None):
    Audit.create_audit_entry(info)
    if arg:
        output = helpers.run_cmd('ps {}'.format(arg))
    else:
        output = helpers.run_cmd('ps')
    return output
```

* **Bypassing Security Measures:** The chapter notes that attackers can attempt to bypass security measures by manipulating GraphQL operation names. This can sometimes avoid audit logging or make malicious requests appear benign.
