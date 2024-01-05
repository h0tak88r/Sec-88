---
description: API3-Broken Object Property Level Authorization (BOPLA)
---

# Mass Assignment Attacks

## Testing Account Registration for Mass Assignment in API Security

### Intercepting and Testing Account Registration for Mass Assignment in crAPI

#### 1. Intercept Account Registration Request

1. Using a browser, submit data for creating a new account in crAPI.
2.  Set FoxyProxy to proxy traffic to Burp Suite.

    ![Intercept Account Registration Request](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/bBPZiv9OQXe8IPvetw56\_MA1.PNG)
3.  Submit the form and ensure the request is intercepted with Burp Suite.

    ![Intercepted Request](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/y4cAWxOLTCmWQglFjmSe\_MA2.PNG)

#### 2. Send Request to Repeater

1. Send the intercepted request to Repeater for further analysis.
2.  Before any attacks, submit a successful request to establish a baseline.

    ![Send Request to Repeater](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/5Dx0FR19RG2qKhtyquOg\_MA3.PNG)

#### 3. Test for Mass Assignment

1. Test the registration process for mass assignment.
2. Attempt to upgrade an account to an administrator role by adding variables used to identify admins.
3. If no admin documentation is available, try adding variables like:
   * "isadmin": true
   * "isadmin": "true"
   * "admin": 1
   * "admin": true
4.  Analyze API responses for any indications of success or failure.

    ![Test for Mass Assignment](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/uyN67TJTNe36mLlcH6Tw\_MA6.PNG)

#### 4. Use Intruder for Further Testing

1. Use Intruder to test various options by placing attack positions around the "isadmin" and "true" values.
2. Set the attack type to cluster bomb and add payloads for positions 1 and 2.
3.  Review results for any unique findings.

    ![Use Intruder for Further Testing](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/vO8TmsEPRwuXEImM3MNP\_MA4.PNG)

#### Fuzzing for Mass Assignment with Param Miner

1.  Ensure Param Miner is installed as a Burp Suite extension.

    ![Param Miner Installation](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/1JzY2pCMQbmln51Omg3X\_MA5.PNG)
2. Right-click on a request to mine parameters using Param Miner.
3.  Configure Param Miner options and click OK.

    ![Configure Param Miner](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/O5NDlXkFScK12mcI3fYP\_MA7.PNG)
4.  Navigate to Extender-Extensions, select Param Miner, and check the Output tab for results.

    ![Param Miner Output](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/5PtTnKVNQpez4cOTgdup\_MA9.PNG)
5. Insert any new parameters detected back into the original request and fuzz for results.

#### Other Mass Assignment Vectors

1. Mass assignment attacks extend beyond becoming an administrator.
2. Explore unauthorized access to other organizations.
3. If user objects include organizational groups, attempt to gain access to those groups.
4. Example: Add an "org" variable to the request and fuzz its value to potentially gain unauthorized access.

#### Hunting for Mass Assignment

1.  Analyze the target API collection for requests that:

    * Accept user input.
    * Have the potential to modify objects.

    ![Hunting for Mass Assignment](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/jNSLM1n3RonguO5mcPtP\_MA10.PNG)
2. Create a new collection for mass assignment testing to avoid damaging the original collection.
3.  Duplicate interesting requests and update unresolved variables.

    ![Duplicate Requests](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/xcmJPdWT2WVNq0P4FOQ2\_MA11.PNG)
4. Understand the purpose of each request in the API collection.
5. Test other endpoints used for updating accounts, group information, user profiles, company profiles, etc.
