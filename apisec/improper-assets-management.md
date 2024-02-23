# Improper Assets Management

### Discovery

To uncover Improper Asset Management vulnerabilities in API security, follow these steps:

1. **Explore API Documentation:** Identify interesting parameters related to user account properties, critical functions, and administrative actions in the API documentation.
2. **Intercept Requests and Responses:** Use tools like Burp Suite to intercept API requests and responses. Analyze the parameters involved and identify those that seem crucial for testing.
3. **Guessing and Fuzzing:** Guess and fuzz parameters in API requests that accept user input. Pay attention to registration processes that allow the creation or editing of account variables.

### Testing Procedure

Follow these steps to test for Improper Asset Management vulnerabilities:

1.  **Baseline Versioning Information:**

    * Understand the baseline versioning information of the API by checking the path, parameters, and headers for versioning details.
    * Use Postman Collection Editor to add a test for detecting a status code 200, indicating a successful response.

    ![Baseline Versioning Information](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/S72WcsuQbeN8lqXzc46C\_IAM1.PNG)
2.  **Run Unauthenticated Baseline Scan:**

    * Run an unauthenticated baseline scan of the API collection using the Postman Collection Runner.
    * Save responses for further analysis.

    ![Run Unauthenticated Baseline Scan](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/jUdhPEQdQymPkG21pimA\_IAM6.PNG)
3.  **Review Results:**

    * Review the results from the unauthenticated baseline scan to understand how the API responds to requests using supported production versioning.

    ![Review Results](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/z5SzbIF0RkGh5tcV9b4m\_IAM5.PNG)
4.  **Find and Replace Collection Versions:**

    * Use "Find and Replace" to turn the collection's current versions into a variable. Do this for all versions (e.g., v2 and v3) in the collection.

    ![Find and Replace Collection Versions](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/bGq8FL27ST25xkG7YL3n\_IAM3.PNG)
5.  **Set Environmental Variable:**

    * Open Postman and navigate to environmental variables.
    * Add a variable named "ver" to the Postman environment and set the initial value to "v1."
    * Update the variable to test for various versioning-related paths (e.g., v1, v2, v3, mobile, internal, test, uat).

    ![Set Environmental Variable](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/RVVSH2FOTtWszQ1LyPze\_IAM4.PNG)
6.  **Run Collection Runner with New Value:**

    * Run the collection runner with the new value set to investigate the results.
    * Analyze responses and look for anomalies.

    ![Run Collection Runner with New Value](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/DzWdP3b7QK6dDmS6R6nZ\_IAM9.PNG)
7. **Identify Anomalies:**
   * Check for differences in responses, especially when requests to paths that do not exist result in Success 200 responses.
   * Anomalies may indicate Improper Asset Management vulnerabilities.
8. **Further Investigation:**
   * Investigate specific requests (e.g., password reset) for anomalies.
   * Identify any differences in responses between versions.
9. **Impact Analysis:**
   * Analyze the impact of the vulnerability discovered. For example, check if the API version allows unlimited attempts for password reset.
10. **Brute Force Testing:**
    * Use tools like WFuzz to perform brute force testing on the API version with potential vulnerabilities.
    * Test the API's response to brute force attempts, especially in areas like OTP verification.

```bash
$ wfuzz -d '{"email":"hapihacker@email.com", "otp":"FUZZ","password":"NewPassword1"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/SecLists-master/Fuzzing/4-digits-0000-9999.txt -u http://crapi.apisec.ai/identity/api/auth/v2/check-otp --hc 500
```

11. **Review Brute Force Results:**
    * Analyze the results of the brute force testing.
    * Look for successful responses and verify if the vulnerability allows unauthorized access or actions.

![Review Brute Force Results](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/RWgS2x0SRSdu2GfFgouz\_IAM14.PNG)

12. **Authenticated User Testing:**
    * Return to the API collection and perform similar tests as an authenticated user to ensure consistent findings.

By following this systematic testing approach, you can effectively identify and exploit Improper Asset Management vulnerabilities in API security. This comprehensive testing strategy helps uncover potential risks and assess their impact on the security of the API.
