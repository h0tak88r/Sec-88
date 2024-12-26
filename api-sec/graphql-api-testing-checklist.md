# GraphQL API Testing Checklist

### Reconnaissance

1. **Port Scanning**: Use Nmap to identify open web application ports.
2. **Endpoint Detection**: Use Graphw00f for GraphQL endpoint detection.
3. **Server Fingerprinting**: Execute Graphw00f's fingerprint mode.
4. **Vulnerability Search**: Check MITRE's CVE database for server vulnerabilities.
5. **Security Features**: Review the GraphQL Threat Matrix.
6. **IDEs Search**: Locate GraphQL IDEs like GraphiQL Explorer with EyeWitness.
7. **Introspection Query**: Send and document available queries, mutations, and subscriptions.
8. **Query Visualization**: Use GraphQL Voyager to visualize introspection responses.

### Denial of Service Testing

1. **Review SDL**: Check for bidirectional relationships in the SDL file.
2. **Test for Vulnerabilities**:
   * Circular queries or fragments
   * Field duplication
   * Alias and directive overloading
   * Query batching
   * Object limits in pagination parameters

### Information Disclosure

1. **Schema Extraction**: Use field stuffing if introspection is disabled.
2. **Error Detection**: Identify debug errors with malformed queries.
3. **Query Tracing**: Look for tracing details in responses.
4. **PII Exposure**: Test for PII transmission using the GET method.

### Authentication and Authorization

1. **Access Tests**:
   * API access without authentication headers
   * Restricted field access via alternate paths
   * API access using GET and POST methods
2. **JWT Validation**: Test JSON Web Token signature validation.
3. **Brute-Force Attacks**:
   * Use alias/array-based batching
   * Employ CrackQL or Burp Suite for brute-forcing

### Injection Testing

1. **Test Points**:
   * Query and field arguments
   * Query directive arguments
   * Operation names
2. **SQL Injection**: Use SQLmap for automatic testing.
3. **OS Command Injection**: Test with Commix.

### Forging Requests

1. **CSRF Testing**:
   * Check for anti-CSRF tokens
   * Explore token bypass possibilities
2. **Request Methods**:
   * Test GET-based queries and mutations
   * Test POST-based state changes

### Hijacking Requests

1. **Server Validation**:
   * Check for WebSocket subscription support
   * Validate the Origin header during handshakes
