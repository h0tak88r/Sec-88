# RECONNAISSANCE

## **Detecting GraphQL APIs**

GraphQL has many implementations written in a variety of programming languages, each of which could have different default configurations or known weaknesses

**GraphQL Implementations and Languages**

<table><thead><tr><th width="242">Server Implementation</th><th>Language</th></tr></thead><tbody><tr><td>Apollo</td><td>TypeScript</td></tr><tr><td>Graphene</td><td>Python</td></tr><tr><td>Yoga</td><td>TypeScript</td></tr><tr><td>Ariadne</td><td>Python</td></tr><tr><td>graphql-ruby</td><td>Ruby</td></tr><tr><td>graphql-php</td><td>PHP</td></tr><tr><td>graphql-go</td><td>Go</td></tr><tr><td>graphql-java</td><td>Java</td></tr><tr><td>Sangria</td><td>Scala</td></tr><tr><td>Juniper</td><td>Rust</td></tr><tr><td>HyperGraphQL</td><td>Java</td></tr><tr><td>Strawberry</td><td>Python</td></tr><tr><td>Tartiflette</td><td>Python</td></tr></tbody></table>

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

If the operation is a query, the result of the operation is the result of executing the operation’s top-level selection set with the query root operation type. An initial value may be provided when executing a query operation: `ExecuteQuery(query, schema, variableValues, initialValue)`

1. Let `queryType` be the root Query type in the schema.
2. Assert: `queryType` is an Object type.
3. Let `selectionSet` be the top-level selection set in the query.
4. Let data be the result of running `ExecuteSelectionSet(selectionSet, queryType, initialValue, variableValues)` normally (allowing parallelization).
5. Let errors be any field errors produced while executing the selection set.
6. Return an unordered map containing data and errors. In practice, this means a GraphQL API will return a data JSON field when there is a result to return to a client’s query. It will also return an errors JSON field whenever errors occur during the execution of a client query.

GraphQL APIs follow a standardized response structure, making them relatively easy to identify during penetration tests or bug bounty hunts. According to the GraphQL specification:

1. **Valid Query Response**:
   * Returns a `data` JSON field containing the requested data.
2. **Invalid Query Response**:
   * Returns an `errors` JSON field with details about the issue.

These predictable behaviors allow automated tools to identify GraphQL APIs by sending test queries and observing responses.

***

### **Nmap Scan**

A common GraphQL response returned when a client makes a GET request.

```bash
curl -X GET http://localhost:5013/graphql
{"errors":[{"message":"Must provide query string."}]}
```

With this information, we now have the ability to automate a scan and pick up any other GraphQL servers that may exist on a network.

{% code overflow="wrap" %}
```bash
nmap -p 5013 -sV --script=http-grep --script-args='match="Must provide query string", http-grep.url="/graphql"' localhost
```
{% endcode %}

***

### The \_\_typename Field

Meta-fields are built-in fields that GraphQL APIs expose to clients. One example is \_\_schema (part of introspection in GraphQL). Another example of a meta-field is \_\_typename. When used, it returns the name of the object type being queried.&#x20;

```graphql
query {
    pastes {
        __typename
    }
}

----------------------
"data": {
    "pastes": [
        {
            "__typename": "PasteObject"
        }
    ]
}
```

As you can see, GraphQL tells us that the pastes object’s type name is PasteObject. The real hack here is that the \_\_typename meta-field can be used against the query root type as well

{% code overflow="wrap" %}
```bash
# Detecting GraphQL by using GET-based queries with Nmap
nmap -p 5013 -sV --script=http-grep --script-args='match="__typename",http-grep.url="/graphql?query=\{__typename\}"' localhost

# Scanning multiple targets defined in a file with Nmap
nmap -p 5013 -iL hosts.txt -sV --script=http-grep --script-args='match="__typename", http-grep.url="/graphql?query=\{__typename\}"'

# Sending a POST-based query using cURL
curl -X POST http://localhost:5013/graphql -d '{"query":"{__typename }"}' -H "Content-Type: application/json"

# A Bash script to automate a POST-based GraphQL detection using cURL
for host in $(cat hosts.txt); do
    curl -X POST "$host" -d '{"query":"{__typename }"}' -H "Content-Type: application/json"
done
```
{% endcode %}

***

### [Graphw00f](https://github.com/dolevf/graphw00f)

GraphQL tool based on Python for detecting GraphQL and performing implementation-level fingerprinting.

Graphw00f allows you to specify a custom list of endpoints when running a scan. If you don’t provide a list, Graphw00f will use its hardcoded list of common endpoints whenever it is tasked with detecting GraphQL.

```bash
# https://github.com/dolevf/graphw00f
cd ~/graphw00f
python3 main.py -d -t http://localhost:5013
python3 main.py -d -t http://localhost:5013 -w wordlist.txt
```

***

### Detecting GraphiQL Explorer and GraphQL Playground

```bash
# EyeWitness
eyewitness --web --single http://localhost:5013/graphiql -d dvga-report

# Scanning multiple URLs with EyeWitness
echo 'http://localhost:5013/graphiql' > urls.txt
eyewitness --web -f urls.txt -d dvga-report
```

<figure><img src="../../.gitbook/assets/image (298).png" alt=""><figcaption><p>An HTML report produced by EyeWitness</p></figcaption></figure>

***

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

**An introspection query in its simplest form**

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

*   Use **GraphQL Voyager** to explore schema relationships:

    1. Navigate to [GraphQL Voyager](https://ivangoncharov.github.io/graphql-voyager/).
    2. Paste the introspection response or upload the SDL file.
    3. View relationships visually (e.g., `PasteObject` links to `OwnerObject`).


* A GraphQL introspection detection with the Nmap NSE

```
nmap --script=graphql-introspection -iL hosts.txt -sV -p 5013
```

***

## Visualizing Introspection with GraphQL Voyager <a href="#h2-502840c04-0008" id="h2-502840c04-0008"></a>

<figure><img src="../../.gitbook/assets/f04007.png" alt=""><figcaption><p> <a href="https://ivangoncharov.github.io/graphql-voyager">https://ivangoncharov.github.io/graphql-voyager</a> or <a href="http://lab.blackhatgraphql.com:9000">http://lab.blackhatgraphql.com:9000</a>,</p></figcaption></figure>

### Generating Introspection Documentation with SpectaQL

> _SpectaQL_ ([https://github.com/anvilco/spectaql](https://github.com/anvilco/spectaql)) is an open source project that allows you to generate static documentation based on an SDL file. The document that gets generated will include information about how to construct queries, mutations, and subscriptions; the different types; and their fields. We’ve hosted an example SpectaQL-generated schema of DVGA at [http://lab.blackhatgraphql.com:9001](http://lab.blackhatgraphql.com:9001) so you can see how SpectaQL looks when it’s functional.
