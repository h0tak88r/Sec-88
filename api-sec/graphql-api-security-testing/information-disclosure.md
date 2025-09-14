# Information Disclosure

### **The Lure of the Schema**

A primary target for attackers is the **GraphQL schema**, which reveals the structure of an application's data. It's like having a map of the database, including all fields and types, and it is often exposed via the **introspection** feature which is enabled by default. This allows hackers to understand the data model, business logic and potential attack vectors. Tools like **InQL** can automate this process, extracting schema information and outputting it in formats that are useful for security testing. However, some GraphQL implementations allow the disabling of introspection, but there are ways around that.

```bash
inql -t http://localhost:5013/graphql --generate-tsv
```

### **Bypassing Disabled Introspection**

Even if introspection is disabled, there are several techniques to gather schema information:

* **Non-Production Environments:** Development and staging environments may have less stringent security than production, and therefore introspection might be enabled. Subdomains like 'staging' or 'dev' are worth checking for GraphQL services with introspection enabled.

{% embed url="https://github.com/dolevf/Black-Hat-GraphQL/blob/master/resources/non-production-graphql-urls.txt" %}

* **The `__type` Meta-field:**&#x20;

The WAF contains rules tailored to GraphQL applications, one of which blocks attempts to introspect the GraphQL API via the `__schema` meta-field but doesn’t take into consideration other introspection meta-fields. The rule itself is defined in JSON in the following way:

This can be used as a "canary" to determine if introspection is disabled. By sending a query using `__type` and checking the response, an attacker can confirm whether the meta-field is available.

```graphql
# A __type introspection canary query
{
    __type(name:"Query") {
    name
    }
}
```

***

* **Field Suggestions:** When a client misspells a field, the server may return a suggestion, which can be abused to discover the fields in the schema. Tools like **Clairvoyance** exploit this feature by sending queries based on a dictionary of common words to reconstruct the schema. The edit-distance algorithm will determine whether suggestions are provided.

```graphql
query {
    pastes {
        owne
    }
}

-----------------
{"errors": [{"message": "Cannot query field \"owne\" on type \"Paste Object\". Did you mean \"owner\" or \"ownerId\"?", "locations": [
{"line": 24,"column": 3}
```

***

* **Field Stuffing:** Attackers insert lists of potential field names into queries to discover additional information. By observing what is returned, they can uncover sensitive fields that are not intended for public access.

{% embed url="https://www.apollographql.com/docs/graphos/schema-design/guides/naming-conventions" %}

```graphql
query {
    user {
        name
        username
        address
        birthday
        age
        password
        sin
        ssn
        apiKey
        token
        emailAddress
        status
    }
}
```

***

#### **Type Stuffing in the \_\_type Meta-field:**

Type stuffing exploits weaknesses in GraphQL's introspection disabling by targeting the `__type` meta-field to uncover schema details.

* **Technique**:
  * By supplying potential type names in the `__type(name:"TypeName")` query, attackers can identify valid types and their fields.
  * For example, querying for `PasteObject` might reveal its fields, such as `id`, `title`, `content`, `public`, and more.
* **Naming Convention**: GraphQL type names typically follow UpperCamelCase, like `PrivatePasteProperties`. Testing these systematically can uncover existing types.
*   **Example Query**:

    ```graphql
    {
      __type(name: "PasteObject") {
        name
        fields {
          name
        }
      }
    }
    ```

    **Response**:

    ```json
    {
      "data": {
        "__type": {
          "name": "PasteObject",
          "fields": [
            {"name": "id"},
            {"name": "title"},
            {"name": "content"},
            {"name": "public"},
            ...
          ]
        }
      }
    }
    ```

***

#### Automating Field Suggestion and Stuffing Using Clairvoyance

{% embed url="https://ivangoncharov.github.io/graphql-voyager" %}

{% code overflow="wrap" %}
```graphql
python3 -m clairvoyance http://localhost:5013/graphql -w ~/high-frequency-vocabulary/30k.txt -o clairvoyance-dvga-schema.json
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>The original DVGA schema</p></figcaption></figure>

Tools like the Custom Word List Generator (CeWL), which comes preinstalled in Kali, can extract keywords from the application’s frontend HTML. Try using the following one-liner to profile and extract information from the DVGA interface:

```bash
cewl http://localhost:5013/
```

This command will return a list of words that you can use in a manual field-stuffing attack. Alternatively, merge it with your list of 30,000 words and use it with Clairvoyance. You can merge two text files by using a simple Bash command:

```bash
paste -d "\n" wordlist1.txt wordlist2.txt > merged_wordlist.txt
```

***

### **Error Messages: A Goldmine for Attackers**

GraphQL’s tendency to return verbose error messages, while helpful for developers, can be exploited. These messages may reveal internal information such as:

* SQL statements used by the server to interact with the database.
* Database column names.
* User credentials.
* **Inferring Information from Stack Traces:**

{% code overflow="wrap" %}
```graphql
query {
    pastes {
        titled
    }
}

---------------------------
{"errors": [{"message": "Cannot query field \"titled\" on type \"PasteObject\".Did you mean \"title\"?","extensions": {"exception": {"stack": [" File \"/Users/dvga-user/Desktop/Damn-Vulnerable-GraphQL-Application/venv/lib/python3.x/site-packages/gevent/baseserver.py\", line 34,in _handle_and_close_when_done\nreturn handle(*args_tuple)\n",--snip--" File \"/Users/dvga-user/Desktop/Damn-Vulnerable-GraphQL-Application/venv/lib/python3.x/site-packages/flask/app.py\", line 2464,in __call__\nreturn self.wsgi_app(environ, start_response)\n",--snip--],"debug": "Traceback (most recent call last):\n File \"/Users/dvga-user/Desktop/Damn-Vulnerable-GraphQL-Application/venv/lib/python3.x/site-packages/flask_sockets.py\", line 40, in __call__\n ..."path": \"/Users/dvga-user/Desktop/Damn-Vulnerable-GraphQL-Application/core/view_override.py"}}}]}
```
{% endcode %}

***

### **Leaking Data via GET Requests**

Some GraphQL implementations allow queries to be sent using the HTTP GET method. This may expose sensitive data, as the data is included in the URL and can be stored in various locations, such as browser history, referrer headers, and proxies.

* **Enabling Debugging:** [**`http://example.com/graphql?debug=1`**](http://example.com/graphql?debug=1)

**Tools of the Trade**

Several tools are mentioned to aid in information disclosure:

* **InQL:** Extracts schema information, assists in fuzzing and brute-forcing, and can be used to automate tasks from the command line.
* **Clairvoyance:** Uses field suggestions to reconstruct the schema when introspection is disabled.
* **Burp Suite:** Used to intercept traffic, capture queries, and observe application behavior.
* **CeWL:** Extracts keywords from the frontend HTML of an application, which can then be used in field-stuffing attacks.
