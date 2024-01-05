---
description: 'API1: Broken Object Level Authorization (BOLA)'
---

# Broken Object Level Authorization (BOLA)

### Broken Object Level Authorization (BOLA)

**Definition:** Broken Object Level Authorization (BOLA) is a security vulnerability that occurs when an application fails to properly enforce access controls on its objects or resources. In the context of APIs, objects or resources can include user accounts, data records, or any other entities that the application manages

### Three Ingredients for Successful BOLA Exploitation

1. **Resource ID:**
   * A unique identifier for a resource (e.g., a number or a complex token).
2. **Requests Accessing Resources:**
   * Knowledge of requests necessary to obtain resources that the current account should not be authorized to access.
3. **Missing or Flawed Access Controls:**
   * Absence of proper access controls, allowing unauthorized access to resources.

### Authorization Testing Strategy

1. **Account Setup:**
   * Create `UserA` account.
2. **Request Exploration:**
   * Use the API as `UserA` to discover requests involving resource IDs.
   * Document requests requiring authorization.
3. **Second Account Creation:**
   * Create `UserB` account.
4. **Token Switch Test:**
   * Obtain a valid `UserB` token and attempt to access `UserA`'s resources.
   * Alternatively, use `UserB`'s resources with `UserA` token.

### Example BOLA Attack

1. **Identify Interesting Request:**
   * Select a request involving a complex resource ID (e.g., vehicle ID).
2. **Capture Request:**
   * Use Burp Suite to capture the request triggered by `UserB`.
3. **Perform BOLA Attack:**
   * Replace `UserB`'s token with `UserA`'s token.
   * Attempt to make the same request with `UserA`'s token.
4. **Successful Exploitation:**
   * Validate successful request with `UserA`'s token.
   * Capture sensitive information (e.g., GPS location, vehicle ID, fullName) belonging to `UserB`.

### Additional Insight: Excessive Data Exposure

* Utilize previously discovered data exposure vulnerabilities.
* Combine BOLA vulnerability with data exposure for a potent Proof of Concept (PoC).
* Highlight severity by demonstrating how BOLA can exploit excessive data exposure.
* Emphasize the importance of robust access controls beyond token complexity.

This approach provides a strong PoC and emphasizes the severity of BOLA vulnerabilities, showcasing their potential impact on data confidentiality and security.\


## Checklist

![Credits ApiSecUniversity](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/expdzRMeT7oYzCVtiZAC\_Authz3.PNG)
