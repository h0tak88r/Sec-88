# GraphQL Communication

## How Do Communications Work in GraphQL?

GraphQL is a flexible query layer between the client and backend, allowing precise data retrieval. Its schema-driven structure ensures strong typing and easy query formation but requires careful design to avoid vulnerabilities like DoS from poorly written resolvers or two-way links.

When a client communicates with a GraphQL server (e.g., to fetch usernames or emails), the client sends a **GraphQL query** via the HTTP POST method. Though data retrieval typically uses the GET method in REST, GraphQL deviates here.

<figure><img src="../../.gitbook/assets/f01001 (2).png" alt=""><figcaption></figcaption></figure>

## **Core Components**

1. **Query Parser**\
   Validates the query’s format and ensures it matches the GraphQL schema. Queries must comply with the application schema to be accepted.
2.  **Schema**\
    The schema defines what data is available for querying. For example:

    ```graphql
    type User {
       username: String
       email: String
    }

    type Location {
       latitude: Int
       longitude: Int
    }
    ```

    * **Object Types:** These are the building blocks of GraphQL schemas, representing data entities (e.g., `User`, `Location`).
    * **Fields:** Attributes specific to objects, such as `username` or `latitude`.
3. **Resolver Functions**\
   These handle data retrieval, e.g., fetching user details from a database.

***

## **Linking Nodes in Schema**

GraphQL schemas allow linking objects using **edges**. For example, a `User` can reference a `Location`:

```graphql
type User {
   username: String
   email: String
   location: Location  # Links User to Location
}

type Location {
   latitude: Int
   longitude: Int
}
```

This enables querying `User` data alongside their `Location`. However, the reverse isn’t possible unless explicitly defined in the schema.

<figure><img src="../../.gitbook/assets/f01003 (1).png" alt=""><figcaption></figcaption></figure>

Two-way links (e.g., allowing both `User` and `Location` to reference each other) should be used cautiously as they can introduce vulnerabilities like denial-of-service (DoS) attacks.<br>

<figure><img src="../../.gitbook/assets/f01004 (1).png" alt=""><figcaption></figcaption></figure>

***

## **Defining Queries**

GraphQL supports three main operation types:

*   **Queries** (read-only operations):

    ```graphql
    query {
       users {
          username
          email
       }
    }
    ```

    Retrieves usernames and emails of all users.
*   **Mutations** (data manipulation):

    ```graphql
    mutation {
       createUser(username: "john", email: "john@example.com") {
          id
       }
    }
    ```

    Adds a new user to the database.
*   **Subscriptions** (real-time updates):

    * _Subscriptions_ are used for real-time communications between clients and GraphQL servers. They allow a GraphQL server to push data to the client when different events occur. Subscriptions typically are used in conjunction with transport protocols such as WebSocket.

    ```graphql
    subscription {
       userUpdates {
          username
          email
       }
    }
    ```

Each query begins with a root type (e.g., `Query`, `Mutation`).

***

## **Query Example with Schema**

Here’s a schema that allows querying users:

```graphql
type User {
   username: String
   email: String
   location: Location
}

type Location {
   latitude: Int
   longitude: Int
}

type Query {
   users: [User]  # Returns an array of User objects
}

schema {
   query: Query
}
```

A corresponding query:

```graphql
query {
   users {
      username
      email
   }
}
```

> Notice that, while field names (like `users`) are lowercase, object names (like `User`) begin with an uppercase letter. This is the most common naming convention in GraphQL schemas.

## **Query Execution**

1. **Parsing & Validation:**\
   The server uses a **query parser** to validate and convert the query into an abstract syntax tree (AST). This ensures compliance with the schema.
2. **Resolver Execution:**\
   Resolvers fetch data (e.g., from a database, file, or another API) and populate the query response.

Resolvers can handle complex tasks, such as making REST API calls, interacting with caching layers, or performing file lookups.
