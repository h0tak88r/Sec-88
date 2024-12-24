# GraphQL Attack Surface

## GraphQL Attack Surface

#### **What Is an Attack Surface?**

An attack surface refers to all potential entry points an attacker can exploit to compromise a system. GraphQL, like any system, has its own unique vulnerabilities based on its features and configuration. These entry points include queries, mutations, subscriptions, and various other elements of the GraphQL language and type system.

Imagine a building with multiple doors and windows. Each entry point is an opportunity for attackers to exploit vulnerabilities. Similarly, GraphQL’s extensive capabilities create opportunities for misconfigurations, improper validation, and exploitation.

***

#### **Core Components of the GraphQL Language**

<table><thead><tr><th width="84">#</th><th width="227">Component</th><th>Description</th></tr></thead><tbody><tr><td>1</td><td>Operation type</td><td>Type that defines the method of interaction with the server (query, mutation, or subscription)</td></tr><tr><td>2</td><td>Operation name</td><td>Arbitrary client-created label used to provide a unique name to an operation</td></tr><tr><td>3</td><td>Top-level field</td><td>Function that returns a single unit of information or object requested within an operation (may contain nested fields)</td></tr><tr><td>4</td><td>Argument (of a top-level field)</td><td>Parameter name used to send information to a field to tailor the behavior and results of that field</td></tr><tr><td>5</td><td>Value</td><td>Data related to an argument sent to a field</td></tr><tr><td>6</td><td>Field</td><td>Nested function that returns a single unit of information or object requested within an operation</td></tr><tr><td>7</td><td>Directive</td><td>Feature used to decorate fields to change their validation or executio</td></tr></tbody></table>

GraphQL queries consist of various components, each of which has security implications:

### **Operation Types**:

* **Query**: Retrieve data.
* **Mutation**: Modify data, such as creating or updating records.
* **Subscription**: Facilitate real-time communication between clients and servers.

**Example: Mutation Query**

```graphql
mutation {
  editPaste(id: 1, content: "My first mutation!") {
    paste {
       id
       title
       content
    }
  }
}

```

This mutation modifies the content of a specific paste while also fetching the updated data. The flexibility in mutation operations can be a source of business logic vulnerabilities.

1. **Subscriptions**: Subscriptions rely on WebSocket connections for real-time updates. While useful, they are prone to vulnerabilities such as Cross-Site WebSocket Hijacking (CSWSH) and Man-in-the-Middle (MITM) attacks if origin validation or encryption (via TLS) is absent.

**Example: WebSocket Handshake**\
Request:

```
GET /subscriptions HTTP/1.1
Host: 0.0.0.0:5013
Connection: Upgrade
Upgrade: websocket

```

Response:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

```

After the handshake, a subscription might look like this:

```graphql
subscription {
  paste {
     id
     title
     content
  }
}
```

**Example: Query with Arguments**

```graphql
query {
  users(id: 1) {
    id
    username
  }
}
```

***

#### **Key Attack Vectors in GraphQL**

1. **Field Suggestions**:\
   When a field is misspelled, GraphQL servers often suggest corrections. This helpful feature can inadvertently expose undocumented fields.

**Example: Error Message with Suggestions**

```
"Cannot query field \\"titl\\" on type \\"PasteObject\\". Did you mean \\"title\\"?"

```

1. **Nested Queries**: GraphQL allows deep nesting, which can lead to recursive queries and potential server overload.

**Example: Circular Field Relationships**

```graphql
{
  id
  title
  content
  owner {
    name
    posts {
      title
      author {
        name
      }
    }
  }
}

```

1. **Argument Exploitation**: Arguments are client-driven and can contain malicious inputs. For example, improperly validated inputs can lead to injection attacks.

**Example: Argument Exploitation**

```graphql
query {
  users(id: "1; DROP TABLE users;") {
    id
    username
  }
}

```

***

#### **Aliases**

Aliases allow renaming fields in GraphQL queries, resolving conflicts when the same field is queried with different arguments. For example:

Without aliases:

```graphql
query {
  pastes(public: false) {
    title
  }
  pastes(public: true) {
    title
  }
}
```

Error: Fields conflict due to differing arguments.

With aliases:

```graphql
query {
  queryOne: pastes(public: false) {
    title
  }
  queryTwo: pastes(public: true) {
    title
  }
}

```

Response:

```json
{
  "data": {
    "queryOne": [{ "title": "My Title!" }],
    "queryTwo": [{ "title": "Testing Testing" }]
  }
}

```

***

#### **Fragments**

Fragments allow reusable field sets for improved readability:

```graphql
fragment CommonFields on PasteObject {
  title
  content
}

query {
  pastes {
    ...CommonFields
  }
}

```

#### Security Implications

From a security perspective, fragments can be constructed such that they reference one another, which can create a circular fragment condition that could lead to denial-of-service (DoS) conditions

. This is because a circular dependency among fragments can lead to an infinite loop when the GraphQL server attempts to resolve the query

For example, consider a scenario with two fragments, Start and End:

```graphql
query {
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

In this case, the Start fragment includes the End fragment, which includes the Start fragment again, creating a circular reference. This can lead to a DoS condition if the server doesn't handle such circular references correctly

***

#### **Variables**

Variables in GraphQL are a way to pass dynamic values to a query, mutation, or subscription, making operations more flexible and reusable. They are defined using a dollar sign ($) symbol followed by a name and a type

```graphql
query publicPastes($status: Boolean!) {
  pastes(public: $status) {
    id
    title
    content
  }
}

```

In this example, $status is a variable of type Boolean that is passed to the public argument of the pastes field. The client would then provide the value for $status as a JSON object, such as {"status": true} or {"status": false}, along with the query

```json
{
  "status": false
}

```

***

#### **Directives**

Directives modify field behavior dynamically. Common directives:

| Name           | Description                              | Location |
| -------------- | ---------------------------------------- | -------- |
| `@skip`        | Omits a field when the condition is true | Query    |
| `@include`     | Includes a field only when true          | Query    |
| `@deprecated`  | Marks a field/type as deprecated         | Schema   |
| `@specifiedBy` | Specifies a scalar type via URL          | Schema   |

Example:

```graphql
query pasteDetails($pasteOnly: Boolean!) {
  pastes {
    id
    title
    content
    owner @skip(if: $pasteOnly) {
      name
    }
  }
}

```

Custom directives like `@computed` can enhance functionality, e.g., merging fields:

```graphql
type User {
  firstName: String
  lastName: String
  fullName: String @computed(value: "$firstName $lastName")
}

```

***

#### **Data Types**

GraphQL supports six types: **Object**, **Scalar**, **Enum**, **Union**, **Interface**, and **Input**.

#### Objects

Custom types with specific fields:

```graphql
type PasteObject {
  id: ID!
  title: String
  content: String
  public: Boolean
}

```

#### Scalars

Core scalar types include `ID`, `Int`, `Float`, `String`, `Boolean`. Implementations can also define their own custom scalars.

```graphql
scalar DateTime
type PasteObject {
		id: ID!
		title: String}
		content: String
		public: Boolean
		userAgent: String
		ipAddr: String
		ownerId: Int
		burn: Boolean
		owner: OwnerObject
		createdAt: DateTime!
	}
```

#### Enums

Enums are special types that allow a field to return only one value from a predefined set of possible values⁠. They are useful when you want to restrict a field to specific options.

Here's how they work:

* You define an enum type by listing all possible values it can have. For example, the UserSortEnum allows sorting users by `ID`, `EMAIL`, `USERNAME`, or `DATE_JOINED⁠⁠`
* When using an enum in a query, you can only use one of these predefined values. For instance, in the example query, users are being sorted by ID:**⁠**

Allow specific values for fields:

```graphql
enum UserSortEnum {
  ID
  EMAIL
  USERNAME
  DATE_JOINED
}

input UserOrderType {
  sort: UserSortEnum!
}

type UserObject {
  id: Int!
  username: String!
}

type Query {
  users(limit: Int, order: UserOrderType): UserObject!
}
```

Example Query:

```graphql
query {
  users(limit: 100, order: { sort: ID })
}

```

#### Unions

Return one of multiple object types:

```graphql
union SearchResults = UserObject | PasteObject
type UserObject {
		id: ID!
		username: String!
}
type PasteObject {
		id: ID!
		title: String
		content: String
		--snip--
}
type Query {
	search(keyword: String): [SearchResults!]
}
```

Query:

```graphql
query {
  search(keyword: "p") {
    ... on UserObject { username }
    ... on PasteObject { title content }
  }
}

---------------
// result
{
"data": {
"search": [
{
"title": "This is my first paste",
"content": "What does your room look like?"
},
{
"id": "2",
"username": "operator"
}}
}
]
```

#### Interfaces

Define common fields across types:

```graphql
interface SearchItem {
	keywords: [String!]
}

type UserObject implements SearchItem {
		id: ID!
		username: String!
		keywords: [String!]
}

type PasteObject implements SearchItem {
		id: ID!
		title: String
		content: String
		keywords: [String!]
		--snip--
}

type Query {
		search(keyword: String): [SearchItem!]!
}
```

#### Inputs

Simplify passing complex arguments:

```graphql
input UserInput {
  username: String!
  password: String!
  email: String!
}

```

Mutation example:

```graphql
mutation newUser($input: UserInput!) {
  createUser(userData: $input) {
    user {
      username
    }
  }
}

```

JSON for variables:

```json
{
  "input": {
    "username": "tom",
    "password": "secret",
    "email": "tom@example.com"
  }
}

```

Apologies for missing the source code earlier. Here's a revised version that includes all relevant queries and responses.

***

#### **GraphQL Introspection**

| Introspection type | Usage                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------- |
| `__Schema`         | Provides all information about the schema of a GraphQL service                              |
| `__Type`           | Provides all information about a type                                                       |
| `__TypeKind`       | Provides the different kinds of types (scalars, objects, interface, union, enum, and so on) |
| `__Field`          | Provides all information for each field of an object or interface type                      |
| `__InputValue`     | Provides field and directive argument information                                           |
| `__EnumValue`      | Provides one of the possible values of an enum                                              |
| `__Directive`      | Provides all information on both custom and built-in directives                             |

1. **Empowering Clients:**
   * Introspection allows clients to discover schema information, including:
     * Queries
     * Mutations
     * Subscriptions
     * Types
     * Fields
     * Directives
   *   Example query for listing all types:

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
               { "name": "ID" },
               { "name": "String" },
               { "name": "OwnerObject" },
               { "name": "UserObject" }
             ]
           }
         }
       }

       ```
2. **Deep Dive into Custom Types:**
   *   Investigate specific types to uncover fields and relationships:

       ```graphql
       query {
         __type(name: "PasteObject") {
           name
           kind
           fields {
             name
             type {
               name
               kind
             }
           }
         }
       }

       ```

       **Response:**

       ```json
       {
         "__type": {
           "name": "PasteObject",
           "kind": "OBJECT",
           "fields": [
             { "name": "id", "type": { "name": null, "kind": "NON_NULL" } },
             { "name": "title", "type": { "name": "String", "kind": "SCALAR" } },
             { "name": "content", "type": { "name": "String", "kind": "SCALAR" } },
             { "name": "owner", "type": { "name": "OwnerObject", "kind": "OBJECT" } }
           ]
         }
       }

       ```

***

#### **Validation and Execution**

1. **Validation Process:**
   * GraphQL queries are checked against the schema for:
     * Field existence
     * Argument correctness
     * Directive support
2. **GraphQL Threat Matrix:**

<figure><img src="../../.gitbook/assets/image (296).png" alt=""><figcaption></figcaption></figure>

* A framework for comparing GraphQL implementations based on:
  * Security maturity
  * Default configurations
  * Known vulnerabilities

1. **Execution Stage:**
   * Resolvers process valid queries, but weak implementations can lead to exploits.
