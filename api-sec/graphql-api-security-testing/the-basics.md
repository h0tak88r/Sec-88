# The Basics

## **What is GraphQL?**

GraphQL is an open-source query and manipulation language for APIs that allows clients to request specific data from a server without receiving unnecessary information. This differs from REST APIs, which return fixed data structures requiring clients to filter out unwanted data.

***

## **How do APIs work in general?**

APIs facilitate communication between applications by enabling requests and responses based on defined rules.

* Example: A browser (like Chrome) communicates with a server through an API to read or alter data.
* Note: API clients aren’t limited to browsers; machines or other servers can also act as clients.

***

## **How does GraphQL differ from REST APIs?**

1. **Data Fetching:**
   * GraphQL allows clients to define exactly what data they need, reducing **over-fetching** and **under-fetching**.
   * REST APIs provide fixed responses, often requiring additional requests for more data or filtering unnecessary data.
2. **Endpoints:**
   * GraphQL uses a single endpoint (e.g., `/graphql`) for all requests.
   * REST APIs expose multiple endpoints, each representing a resource (e.g., `/users`, `/history`).
3. **HTTP Methods:**
   * GraphQL primarily uses the `POST` method for all operations, though it can also support `GET`.
   * REST APIs use specific methods (`GET`, `POST`, `PUT`, `DELETE`) to define operations.
4. **Error Handling:**
   * REST APIs rely on HTTP status codes (e.g., `404 Not Found`, `401 Unauthorized`) to indicate errors.
   *   GraphQL typically returns `200 OK` for responses, even for errors, which are detailed in the response body under an `errors` field:

       ```json
       {
          "errors": [
            {
              "message": "Cannot query field 'usernam'. Did you mean 'username'?"
            }
          ]
       }
       ```

***

## **What Problems Does GraphQL Solve?**

1. **Efficiency in Data Fetching:**\
   Clients can retrieve the exact data they need in a single query, improving performance by:
   * Avoiding **over-fetching** (getting unnecessary data).
   * Avoiding **under-fetching** (needing multiple requests for complete data).
2. **Schema Federation and Stitching:**
   * **Schema Stitching:** Combines multiple GraphQL schemas into one, enabling a unified API gateway.
   * **Schema Federation:** Automates stitching by letting the gateway find and consolidate schemas dynamically.\
     These features simplify integration for clients but increase complexity, potentially introducing security risks.

***

## **What are some security advantages and risks of GraphQL?**

**Advantages:**

* By returning only the requested data, GraphQL reduces the risk of exposing sensitive information like PII (personally identifiable information).

**Risks:**

* **Complexity:** Features like schema federation can lead to security vulnerabilities.
* **GET Method Usage:** GraphQL queries over `GET` can introduce vulnerabilities, such as Cross-Site Request Forgery (CSRF).
* **Single Endpoint:** A consistent endpoint (e.g., `/graphql`) may expose sensitive data if not secured properly.

***
