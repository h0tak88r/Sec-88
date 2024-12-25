# Information Disclosure

**The Lure of the Schema**

A primary target for attackers is the **GraphQL schema**, which reveals the structure of an application's data. It's like having a map of the database, including all fields and types, and it is often exposed via the **introspection** feature which is enabled by default. This allows hackers to understand the data model, business logic and potential attack vectors. Tools like **InQL** can automate this process, extracting schema information and outputting it in formats that are useful for security testing. However, some GraphQL implementations allow the disabling of introspection, but there are ways around that.

**Bypassing Disabled Introspection**

Even if introspection is disabled, there are several techniques to gather schema information:

* **Non-Production Environments:** Development and staging environments may have less stringent security than production, and therefore introspection might be enabled. Subdomains like 'staging' or 'dev' are worth checking for GraphQL services with introspection enabled.
* **The `__type` Meta-field:** This can be used as a "canary" to determine if introspection is disabled. By sending a query using `__type` and checking the response, an attacker can confirm whether the meta-field is available.
* **Field Suggestions:** When a client misspells a field, the server may return a suggestion, which can be abused to discover the fields in the schema. Tools like **Clairvoyance** exploit this feature by sending queries based on a dictionary of common words to reconstruct the schema. The edit-distance algorithm will determine whether suggestions are provided.
* **Field Stuffing:** Attackers insert lists of potential field names into queries to discover additional information. By observing what is returned, they can uncover sensitive fields that are not intended for public access.

**Error Messages: A Goldmine for Attackers**

GraphQL’s tendency to return verbose error messages, while helpful for developers, can be exploited. These messages may reveal internal information such as:

* SQL statements used by the server to interact with the database.
* Database column names.
* User credentials.

**Leaking Data via GET Requests**

Some GraphQL implementations allow queries to be sent using the HTTP GET method. This may expose sensitive data, as the data is included in the URL and can be stored in various locations, such as browser history, referrer headers, and proxies.

**Tools of the Trade**

Several tools are mentioned to aid in information disclosure:

* **InQL:** Extracts schema information, assists in fuzzing and brute-forcing, and can be used to automate tasks from the command line.
* **Clairvoyance:** Uses field suggestions to reconstruct the schema when introspection is disabled.
* **Burp Suite:** Used to intercept traffic, capture queries, and observe application behavior.
* **CeWL:** Extracts keywords from the frontend HTML of an application, which can then be used in field-stuffing attacks.

**Key Takeaways**

Information disclosure in GraphQL can stem from many different architectural, technical, or process-level mistakes, with default settings being a major contributor. Introspection is the key to unlocking the structure of the API, but even when it's disabled, there are still ways to expose the schema. By combining different techniques and tools, an attacker can get a deep understanding of the API and potentially access sensitive data. Understanding these attack vectors is crucial for both security professionals and developers looking to protect their GraphQL APIs.
