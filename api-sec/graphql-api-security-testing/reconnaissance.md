# RECONNAISSANCE

## **Detecting GraphQL APIs**

GraphQL has many implementations written in a variety of programming languages, each of which could have different default configurations or known weaknesses

**GraphQL Implementations and Languages**

| Server Implementation | Language   |
| --------------------- | ---------- |
| Apollo                | TypeScript |
| Graphene              | Python     |
| Yoga                  | TypeScript |
| Ariadne               | Python     |
| graphql-ruby          | Ruby       |
| graphql-php           | PHP        |
| graphql-go            | Go         |
| graphql-java          | Java       |
| Sangria               | Scala      |
| Juniper               | Rust       |
| HyperGraphQL          | Java       |
| Strawberry            | Python     |
| Tartiflette           | Python     |

## Common Endpoints

```http
/graphql
/graphiql
/v1/graphql
/v2/graphql
/v3/graphql
/v1/graphiql
/v2/graphiql
/v3/graphiql
/playground
/v1/playground
/v2/playground
/v3/playground
/api/v1/playground
/api/v2/playground
/api/v3/playground
/console
/api/graphql
/api/graphiql
/explorer
/api/v1/graphql
/api/v2/graphql
/api/v3/graphql
/api/v1/graphiql
/api/v2/graphiql
/api/v3/graphiql
```

* Endpoints like `/graphql` or IDE endpoints (`/graphiql`, `/playground`) are common but can \
  be customized.

**Example Endpoint Definition in Graphene:**

Graphene, a Python-based implementation of GraphQL, can expose two endpoints, one for GraphQL, and the other for GraphiQL Explorer, which is built into Graphene:

```python
app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
  'graphql',
  schema=schema
))
app.add_url_rule('/graphiql', view_func=GraphQLView.as_view(
  'graphiql',
  schema=schema,
  graphiql=True
))
```

## **Common GraphQL Responses**

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

GraphQL APIs follow a standardized response structure, making them relatively easy to identify during penetration tests or bug bounty hunts. According to the GraphQL specification:

1. **Valid Query Response**:
   * Returns a `data` JSON field containing the requested data.
2. **Invalid Query Response**:
   * Returns an `errors` JSON field with details about the issue.

These predictable behaviors allow automated tools to identify GraphQL APIs by sending test queries and observing responses.

***

#### **Example of Valid Query Response**

Send a query to fetch the `id` field from the `pastes` object using the **HTTP POST** method:

```graphql
query {
  pastes {
    id
  }
}
```

**Response**:

```json
{
  "data": {
    "pastes": [
      {
        "id": "1"
      }
    ]
  }
}
```

***

#### **Example of Invalid Query Response**

Send an invalid query referencing a non-existent field (`badfield`):

```graphql
query {
  badfield {
    id
  }
}
```

**Response**:

```json
{
  "errors": [
    {
      "message": "Cannot query field \"badfield\" on type \"Query\".",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ]
    }
  ]
}
```

***

## **GraphQL Fingerprinting**

### **Introspection**

**State of Introspection in GraphQL Implementations (Table 4-2)**

| Language | Implementation | Introspection Default | Disable Option |
| -------- | -------------- | --------------------- | -------------- |
| Python   | Graphene       | Enabled               | No             |
| Python   | Ariadne        | Enabled               | Yes            |
| PHP      | graphql-php    | Enabled               | Yes            |
| Go       | graphql-go     | Enabled               | No             |
| Ruby     | graphql-ruby   | Enabled               | Yes            |
| Java     | graphql-java   | Enabled               | No             |

**Example Introspection Query**

```graphql
query {
  __schema {
    types {
      name
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "__schema": {
      "types": [
        { "name": "PasteObject" },
        { "name": "CreatePaste" }
      ]
    }
  }
}
```

**Visualizing Introspection Data**

* Use **GraphQL Voyager** to explore schema relationships:
  1. Navigate to [GraphQL Voyager](https://ivangoncharov.github.io/graphql-voyager/).
  2. Paste the introspection response or upload the SDL file.
  3. View relationships visually (e.g., `PasteObject` links to `OwnerObject`).

***

### **Meta-Fields for Detection**

**The `__typename` Meta-Field**

GraphQL provides built-in meta-fields like `__typename`, which reveal the type of an object being queried.

**Example Query:**

```graphql
query {
  pastes {
    __typename
  }
}
```

**Response:**

```json
{
  "data": {
    "pastes": [
      {
        "__typename": "PasteObject"
      }
    ]
  }
}
```

**Example Query at Root Level:**

```graphql
query {
  __typename
}
```

**Response:**

```json
{
  "data": {
    "__typename": "Query"
  }
}
```

* **Purpose:** Useful for detecting GraphQL without prior knowledge of the schema.

***

**Automating Detection with Nmap**

**Example 2: Using `__typename`**

Command:

```bash
nmap -p 5013 -sV --script=http-grep --script-args='match="__typename", http-grep.url="/graphql?query={__typename}"' localhost
```

Output:

```plaintext
PORT     STATE SERVICE VERSION
5013/tcp open  http    Werkzeug httpd
| http-grep:
|   (1) http://localhost:5013/graphql?query={__typename}:
|     (1) User Pattern 1:
|_      + __typename
```

**Example 3: Scanning Multiple Hosts**

Command:

```bash
nmap -p 5013 -iL hosts.txt -sV --script=http-grep --script-args='match="__typename", http-grep.url="/graphql?query={__typename}"'
```

* **hosts.txt** contains a list of target IPs or domain names.

***

### **Detecting GraphQL with cURL**

**Using HTTP POST**

Command:

```bash
curl -X POST http://localhost:5013/graphql -d '{"query":"{__typename}"}' -H "Content-Type: application/json"
```

**Automating with Bash**

Command:

```bash
for host in $(cat hosts.txt); do
  curl -X POST "$host" -d '{"query":"{__typename}"}' -H "Content-Type: application/json"
done
```

* **hosts.txt:** Contains a list of full target URLs.

***

### **Graphw00f for Detection**

**Description:** Graphw00f is a Python-based tool for detecting GraphQL and fingerprinting implementations.

**Common Endpoints in Graphw00f**

| Endpoint      | Notes       |
| ------------- | ----------- |
| `/graphql`    | Default     |
| `/console`    | Alternative |
| `/playground` | IDE         |
| `/gql`        | Shortened   |
| `/query`      | Query path  |

**Command for Detection**

Command:

```bash
python3 main.py -d -t http://localhost:5013
```

Output:

```plaintext
[*] Checking http://localhost:5013/
[*] Checking http://localhost:5013/graphql
[!] Found GraphQL at http://localhost:5013/graphql
```

***

### **Detecting GraphQL IDEs**

**GraphiQL and GraphQL Playground**

These IDEs are JavaScript-based and often overlooked by traditional scanners.

**Using EyeWitness**

EyeWitness captures screenshots of web pages to detect graphical interfaces.

Command:

```bash
eyewitness --web --single http://localhost:5013/graphiql -d dvga-report
```

Output:

```plaintext
[*] Done! Report written in the dvga-report folder!
Would you like to open the report now? [Y/n]
```

**Output Report:**

* Includes screenshots and source code of detected web pages.
* Stored in folders like `screens`, `source`, and `report.html`.

***

**Building Custom Wordlists**

**Creating URL Lists for EyeWitness:** Command:

```bash
for i in $(cat /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt); do
  echo http://localhost:5013/$i >> urls.txt
done
```

* Appends each directory in the wordlist to the base URL.

***
