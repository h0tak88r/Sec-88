---
description: 'CWE-639: Authorization Bypass Through User-Controlled Key'
---

# Insecure Direct Object References (IDOR)

## **Understanding Insecure Direct Object References (IDOR)**

#### **What is IDOR?**

Insecure Direct Object References (IDOR) occur when an application uses user-supplied input to access objects directly without proper access control checks. This vulnerability can lead to unauthorized access to data or functions, enabling attacks such as horizontal and vertical privilege escalation.

#### **How IDOR Occurs**

IDOR vulnerabilities typically arise when the application fails to verify if a user is authorized to access or manipulate an object. These vulnerabilities are most commonly associated with horizontal privilege escalation (accessing data of other users at the same privilege level) but can also involve vertical privilege escalation (accessing data or functions reserved for higher privilege levels).

***

#### **6. C#/.NET Example (ASP.NET MVC)**

**Scenario:** An ASP.NET MVC application allows users to view their orders by passing an order ID in the query string.

**Vulnerable Code:**

```csharp
// Vulnerable code: No access control check
public ActionResult ViewOrder(int orderId)
{
    var order = db.Orders.Find(orderId);
    return View(order);
}
```

**Explanation:**

* The application directly uses the `orderId` parameter to retrieve order information.
* An attacker can modify the `orderId` in the query string to view orders belonging to other users.

***

## **Checklist for Testing IDOR Vulnerabilities**

#### **1. Identify User-Controlled Parameters**

* Review URLs, POST bodies, headers, and cookies for parameters that reference objects (e.g., `user_id`, `file_id`, etc.).
* Look for identifiers exposed in client-side code or API responses.

#### **2. Test Parameter Manipulation**

* Attempt to change the parameter value to that of another user’s ID or object reference.
* Observe if unauthorized data or functions are exposed.

#### **3. Examine API Endpoints**

* Review RESTful API endpoints for object references in URLs or request bodies.
* Test different object IDs in API requests to see if unauthorized data is returned.

#### **4. Test with Different User Roles**

* Use accounts with different privilege levels (e.g., admin, regular user, guest) to test if object references can be used to escalate privileges.\`\`

{% hint style="info" %}
**Pro Tip:**

1. **Identify Authentication Methods:** Make sure to capture the session cookie, authorization header, or any other form of authentication used in requests.
2. **Use Auth-Analyzer in Burp Suite:** Pass these authentication tokens to the Auth-Analyzer Burp extension. This tool will replay all requests with the captured session information.
3. **Test with Another User:** Log in as a different user and activate the Auth-Analyzer extension. If you see the `SAME` tag in the extension results, this could indicate an IDOR vulnerability.
4. **Manual Verification:** Always manually check the request to confirm whether the vulnerability is genuine.
5. **Assess ID Predictability:** Determine if the IDs are predictable. If they aren't, investigate where they might be leaked, such as in other API responses. This could help in further exploitation or verification of the vulnerability.
{% endhint %}

## **UUID/GUID**

UUID (Universally Unique Identifier) or GUID (Globally Unique Identifier) is a 128-bit number used to uniquely identify information in computer systems. They are widely used in databases, software development, and distributed systems to ensure that identifiers are unique across different systems and times.

UUIDs are typically represented as a series of hexadecimal digits, often split into five groups, separated by hyphens. For example: `123e4567-e89b-12d3-a456-426614174000`.

#### Types of UUID

Tools for decoding and analyzing UUIDs

{% embed url="https://www.uuidtools.com/decode" %}

The version and variant are encoding within UUIDs.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Version Digit ("M")**

| Hex Digit | UUID Version    |
| --------- | --------------- |
| 1         | version-1       |
| 2         | version-2       |
| 3         | version-3       |
| 4         | version-4       |
| 5         | version-5       |
| 6 - f, 0  | version unknown |

**Variant digit ("N")**

| Binary Representation ‡ | Hex Digit | Variant                              |
| ----------------------- | --------- | ------------------------------------ |
| 0xxx                    | 0 - 7     | reserved (NCS backward compatible)   |
| 10xx                    | 8 - b     | DCE 1.1, ISO/IEC 11578:1996          |
| 110x                    | c - d     | reserved (Microsoft GUID)            |
| 1110                    | e         | reserved (future use)                |
| 1111                    | f         | unknown / invalid. Must end with "0" |

* Nil UUID – Version 0

```
00000000-0000-0000-0000-000000000000
```

Usually used for fixed UUIDs like for testing accounts and default credentials,.............

* Time-based UUID – Version 1

```
e6e3422c-c82d-11ed-8761-3ff799965458
```

this kind of UUIDs is time and node based and the  Clock part is usually random

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

As you might expect, relying on UUID v1 for sensitive actions is inherently insecure. In this video, a scenario is demonstrated where an application uses UUID v1 as a token for password resets. An attacker can easily extract other users' UUIDs (eg. from creating account or API calls), determine the timestamp, and either manually generate valid password reset tokens or brute-force the clock component.

{% embed url="https://www.youtube.com/watch?v=an69nKkLEBM" %}

* DCE Security UUID – Version 2

```
b165e8c6-5e9a-21ea-9e00-0242ac130003
```

* Name-based UUID - Version 3 and 5

```
18f99f82-61f7-3530-8d8a-8fdf2cd0cae0
b21b95a4-56c3-51de-8828-1bb7bd249fd2
```

* Randomly Generated GUID - Version 4

```
0d706e07-75b5-4553-8abd-6c3d52fdbf70
```

***

## **Hacking Unpredictable IDORs**

{% embed url="https://imgur.com/a/VrquUx6" %}

Unpredictable IDs may seem secure, but there are various ways they can still be found:

*   [ ] &#x20;**Wayback Machine:** This archive service can store old URLs, which might contain unpredictable IDs. You can search it using:

    {% code overflow="wrap" %}
    ```
    https://web.archive.org/cdx/search/cdx?url=*.test.com/*&output=text&fl=original&collapse=urlkey
    ```
    {% endcode %}
*   [ ] **AlienVault OTX:** This threat intelligence platform inadvertently archives URLs, which might have unpredictable IDs in parameters or paths. Use the API:

    ```
    https://otx.alienvault.com/api/v1/indicators/{TYPE}/{DOMAIN}/url_list?limit=500
    ```
*   [ ] **URLScan:** This tool scans websites for malicious content, often logging unpredictable IDs in URLs:

    ```
    https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=10000
    ```
*   [ ] **Common Crawl:** This project archives web pages, which may contain unpredictable IDs:

    ```
    https://commoncrawl.org/
    ```
*   [ ] **VirusTotal:** This service analyzes suspicious URLs, which might leak IDs:

    ```
    https://www.virustotal.com/vtapi/v2/domain/report?apikey={APIKEY}&domain={DOMAIN}
    ```
* [ ] **Atomated tools:** Collect urls using automated ools like waymore,waybackurls and gau and then using regex extract urls that otains uuids on it&#x20;

{% embed url="https://github.com/xnl-h4ck3r/waymore" %}

* [ ] **Google Search:** Google indexes URLs that might contain IDs in paths or parameters. Cached pages may also expose IDs.
* [ ] **GitHub Search:** Public GitHub repositories might contain requests or scripts where users inadvertently hardcode unpredictable IDs.
* [ ] **Insider Threat - Previous Employee:** A former employee could have logged or memorized IDs before leaving, making them vulnerable.
* [ ] **Insider Threat - RO User:** A read-only user within an organization might be able to view unpredictable IDs, leading to potential privilege escalation.
* [ ] **Referrer Header:** When an ID is passed in a URL, the referrer header can leak it to other servers.
* [ ] **Browser History:** Access to a browser’s history can reveal IDs in URLs.
* [ ] **Web Logs:** HTTP logs, whether accessed by IT staff, VPN providers, or ISPs, can contain unpredictable IDs in URLs.
* [ ] **Unknown or Future Bug:** Even if no current method exists to leak IDs, future bugs could create vulnerabilities.
* [ ] **Predictability Flaws:** Many "unpredictable" IDs may have flaws, making them easier to predict than intended.
* [ ] **Clickjacking:** This technique can be used to steal unpredictable IDs.
* [ ] **OAuth Buttons:** "Sign in with" OAuth buttons might expose organization UUIDs in URLs.
* [ ] **Accidental Screen Share:** Screen sharing can expose URLs with UUIDs, making them vulnerable to IDOR attacks.
* [ ] **Hard-Coded IDs:** Developers might accidentally hard-code UUIDs, creating vulnerabilities.
* [ ] **It might not be unpredictable**: Any cryptography expert will tell you “random” with computers is very hard. It’s one reason why [Cloudflare uses lava lamps](https://blog.cloudflare.com/randomness-101-lavarand-in-production/). Many “unpredictable” IDs may actually have a design flaw which leads to predictability, Some times it is as easy to guess as `timestamp + machine ID`

{% embed url="https://x.com/0xLupin/status/1745805050562105739" %}

* [ ] **Fixed-IDs**

> Interestingly, the application used some fixed UUIDs like 00000000-0000-0000-0000-000000000000 and 11111111-1111-1111-1111-111111111111 for some \_administrative\_ users

{% embed url="https://x.com/MrTuxracer/status/1560639161966555141?s=20&t=3WJ-KgS7GeBe3ZM_vXqkNQ" %}

* [ ] **OLD UUIDs:** If you can leak some old IDs using wayback machine for instance, you might be able to brute force sequentially the ones after.

{% embed url="https://x.com/0xLupin/status/1745813550260515322" %}

## **Code Examples**

#### **1. PHP Example**

```php
// Incorrect (Vulnerable)
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $query);

// Correct (Secure)
session_start();
$current_user_id = $_SESSION['user_id'];
$query = "SELECT * FROM users WHERE id = $current_user_id";
$result = mysqli_query($conn, $query);
```

#### **2. JavaScript/Node.js Example**

```javascript
// Incorrect (Vulnerable)
app.get('/user/:id', (req, res) => {
  const user = db.users.find(req.params.id);
  res.send(user);
});

// Correct (Secure)
app.get('/user/:id', (req, res) => {
  const user = db.users.find(req.params.id);
  if (user.id !== req.session.userId) {
    return res.status(403).send('Access Denied');
  }
  res.send(user);
});
```

#### **3. Python/Flask Example**

```python
# Incorrect (Vulnerable)
@app.route('/user/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.serialize())

# Correct (Secure)
@app.route('/user/<int:user_id>')
def get_user(user_id):
    if user_id != current_user.id:
        return jsonify({"error": "Access Denied"}), 403
    user = User.query.get(user_id)
    return jsonify(user.serialize())
```

***

## **Prevention Techniques**

* Always verify that the user is authorized to access or modify the object.
* Use session or JWT tokens to determine the current user instead of relying on user-controlled parameters.
* Avoid Exposing Identifiers in URLs

***

## Resources

{% embed url="https://josephthacker.com/hacking/cybersecurity/2022/08/18/unpredictable-idors.html" %}

{% embed url="https://portswigger.net/web-security/access-control/idor" %}

{% embed url="https://github.com/xnl-h4ck3r/waymore" %}

{% embed url="https://danaepp.com/attacking-predictable-guids-when-hacking-apis" %}
