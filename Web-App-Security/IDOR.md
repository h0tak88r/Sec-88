---
tags:
  - web-app-security
---
# IDOR Checklist

- [ ] Find and Replace 10s in `urls`, headers and body: /users/01 → /users/02
- [ ] Try Parameter Pollution: users-01 users-01&users-02
- [ ] Special Characters: `/users/01` of `/users/*` → Disclosure of every single user
- [ ] Try Older versions of `api` endpoints: `/api/v3/users/01` → `/api/v1/users/02`
- [ ] Add extension: `/users/01` → `/users/82.json`
- [ ] Change Request Methods: `POST /users/81` → `GET, PUT, PATCH, DELETE` etc
- [ ] Check if `Referer` or some other `Headers` are used to validate the `IDs`:  
    `GET /users/02` → `403 Forbidden Referer: [example.com/users/01](<http://example.com/users/01>) GET /users/82` → `200 OK Referer: [example.com/users/02](<http://example.com/users/02>)`
- [ ] Encrypted IDs: If application is using encrypted IDs, try to decrypt using [hashes.com](http://hashes.com/) or other tools.
- [ ] Swap GUID with Numeric ID or email:  
    `/users/1b84c196-89f4-4260-b18b-ed85924ce283` or `/users/82` or `/users/agb.com`
- [ ] Try GUIDs such as:  
    `00000000-0000-0000-0000-000000000000` and `11111111-1111-1111-1111-111111111111`
- [ ] GUID Enumeration: Try to disclose GUIDs using `Google Dorks`, `Github`, `Wayback`, `Burp history`
- [ ] If none of the GUID Enumeration methods work then try: `Signup`, `Reset Password`, Other endpoints within application and analyze response. These endpoints mostly disclose user's GUID.
- [ ] `403/401` Bypass: If server responds back with a `403/401` then try to use burp intruder and  
    send `50-100` requests having different IDs: Example: from `/users/01` to `/users/100`
- [ ] if server responds with a `403/401`, double check the function within the application.  
    Sometime `403/401` is thrown but the action is performed.
- [ ] Blind IDORS: Sometimes information is not directly disclosed. Lookout for endpoints and  
    features that may disclose information such as `export files`, `emails` or `message alerts`.
- [ ] Chain `IDOR` with `XSS` for `Account Takeovers`.
- [ ] Bruteforce Hidden HTTP parameters
- [ ] send wildcard instead of an id
- [ ] Missing Function Level Acess Control
- [ ] Bypass object level authorization Add parameter onto the endpoit if not present by defualt

```
GET /api_v1/messages ->200GET /api_v1/messages?user_id=victim_uuid ->200
```

- [ ] HTTP Parameter POllution Give mult value for same parameter

```
GET /api_v1/messages?user_id=attacker_id&user_id=victim_idGET /api_v1/messages?user_id=victim_id&user_id=attacker_id
```

- [ ] change file type

```
GET /user_data/2341        -> 401GET /user_data/2341.json   -> 200GET /user_data/2341.xml    -> 200GET /user_data/2341.config -> 200GET /user_data/2341.txt    -> 200
```

- [ ] json parameter pollution

```
{"userid":1234,"userid":2542}
```

- [ ] Wrap the ID with an array in the body

```
{"userid":123} ->401{"userid":[123]} ->200
```

- [ ] wrap the id with a json object

```
{"userid":123} ->401{"userid":{"userid":123}} ->200
```

- [ ] Test an outdata API version

```
GET /v3/users_data/1234 ->401GET /v1/users_data/1234 ->200
```

- [ ] If the website using graphql, try to find IDOR using graphql!

- `exif_geo`
    
    ### Summary
    
    When a user uploads an image in [example.com](http://example.com/), the uploaded image’s EXIF Geolocation Data does not gets stripped. As a result, anyone can get sensitive information of [example.com](http://example.com/) users like their Geolocation, their Device information like Device Name, Version, Software & Software version used etc.
    
    ### Steps to reproduce:
    
    1. Got to Github ( [https://github.com/ianare/exif-samples/tree/master/jpg](https://github.com/ianare/exif-samples/tree/master/jpg)) <br>
    2. There are lot of images having resolutions (i.e 1280 * 720 ) , and also whith different MB’s
    3. Go to Upload option on the website
    4. Upload the image
    5. see the path of uploaded image ( Either by right click on image then copy image address OR right click, inspect the image, the URL will come in the inspect , edit it as html )</br>
    6. open it ([http://exif.regex.info/exif.cgi](http://exif.regex.info/exif.cgi))
    7. See `wheather` is that still showing `exif` data , if it is then Report it.
    
    # Reports (Hackerone)
    
    - [IDOR with Geolocation data not stripped from images](https://hackerone.com/reports/906907)
    
    ## Insecure Direct Object Reference (IDOR)
    
    - [Disclose Private Dashboard Chart's name and data in Facebook Analytics](https://bugreader.com/jubabaghdad@disclose-private-dashboard-charts-name-and-data-in-facebook-analytics-184)
    - [Disclosing privately shared gaming clips of any user](https://bugreader.com/rony@disclosing-privately-shared-gaming-clips-of-any-user-128)
    - [Adding anyone including non-friend and blocked people as co-host in personal event!](https://bugreader.com/binit@adding-anyone-including-non-friend-and-blocked-people-as-co-host-in-personal-event-181)
    - [Page analyst could view job application details](https://bugreader.com/rony@page-analyst-could-view-job-application-details-213)
    - [Deleting Anyone's Video Poll](https://bugreader.com/testgrounds@deleting-anyones-video-poll-175)
- Try decode the ID, if the ID encoded using md5,base64,etc
```html
GET /GetUser/dmljdGltQG1haWwuY29t
[...]
```

- change HTTP method
```bash
GET /users/delete/victim_id  ->403
POST /users/delete/victim_id ->200
```

- Try replacing parameter names
```bash
Instead of this:
GET /api/albums?album_id=<album id>

Try This:
GET /api/albums?account_id=<account id>

Tip: There is a Burp extension called Paramalyzer which will help with this by remembering all the parameters you have passed to a host.
```

-  Path Traversal
```bash
POST /users/delete/victim_id          ->403
POST /users/delete/my_id/..victim_id  ->200
```

- change request content-type
```bash
Content-Type: application/xml ->
Content-Type: application/json
```

-  swap non-numeric with numeric id
```bash
GET /file?id=90djbkdbkdbd29dd
GET /file?id=302
```

-  Missing Function Level Acess Control 
```bash
GET /admin/profile ->401
GET /Admin/profile ->200
GET /ADMIN/profile ->200
GET /aDmin/profile ->200
GET /adMin/profile ->200
GET /admIn/profile ->200
GET /admiN/profile ->200
```

- send wildcard instead of an id
```bash
GET /api/users/user_id ->
GET /api/users/*
```

-  Never ignore encoded/hashed ID
```bash
for hashed ID ,create multiple accounts and understand the ppattern application users to allot an iD
```

-  Google Dorking/public form
```bash
search all the endpoints having ID which the search engine may have already indexed
```

-  Bruteforce Hidden HTTP  parameters
```bash
use tools like arjun , paramminer 
```

-  Bypass object level authorization Add parameter onto the endpoit if not present by defualt
```bash
GET /api_v1/messages ->200
GET /api_v1/messages?user_id=victim_uuid ->200
```

-  HTTP Parameter POllution Give mult value for same parameter
```bash
GET /api_v1/messages?user_id=attacker_id&user_id=victim_id
GET /api_v1/messages?user_id=victim_id&user_id=attacker_id
```

-  change file type
```bash
GET /user_data/2341        -> 401
GET /user_data/2341.json   -> 200
GET /user_data/2341.xml    -> 200
GET /user_data/2341.config -> 200
GET /user_data/2341.txt    -> 200
```

-  json parameter pollution
```bash
{"userid":1234,"userid":2542}
```
- Wrap the ID with an array in the body
```bash
{"userid":123} ->401
{"userid":[123]} ->200
```

-  wrap the id with a json object
```bash
{"userid":123} ->401
{"userid":{"userid":123}} ->200
```

-  Test an outdata API version 
```bash
GET /v3/users_data/1234 ->401
GET /v1/users_data/1234 ->200
```

-  If the website using graphql, try to find IDOR using graphql!
```bash
GET /graphql
[...]
```
```html
GET /graphql.php?query=
[...]
```
# [Top IDOR Reports](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPIDOR.md)
1. [IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users](https://hackerone.com/reports/415081) to PayPal - 694 upvotes, $10500
2. [IDOR allow access to payments data of any user](https://hackerone.com/reports/751577) to Nord Security - 337 upvotes, $0
3. [Insecure Direct Object Reference (IDOR) - Delete Campaigns  ](https://hackerone.com/reports/1969141) to HackerOne - 280 upvotes, $0
4. [idor allows you to delete photos and album from a gallery](https://hackerone.com/reports/380410) to Pornhub - 266 upvotes, $1500
5. [IDOR allows any user to edit others videos](https://hackerone.com/reports/681473) to Pornhub - 246 upvotes, $1500
6. [Singapore - Account Takeover via IDOR](https://hackerone.com/reports/876300) to Starbucks - 221 upvotes, $0
7. [IDOR delete any Tickets on ads.tiktok.com](https://hackerone.com/reports/1475520) to TikTok - 193 upvotes, $0
8. [I.D.O.R To Order,Book,Buy,reserve On YELP FOR FREE (UNAUTHORIZED USE OF OTHER USER'S CREDIT CARD)](https://hackerone.com/reports/391092) to Yelp - 181 upvotes, $0
9. [IDOR when editing users leads to Account Takeover without User Interaction at CrowdSignal](https://hackerone.com/reports/915114) to Automattic - 178 upvotes, $0
10. [An IDOR that can lead to enumeration of a user and disclosure of email and phone number within cashier](https://hackerone.com/reports/1966006) to Unikrn - 167 upvotes, $3000
11. [IDOR allows an attacker to modify the links of any user](https://hackerone.com/reports/1661113) to Reddit - 159 upvotes, $5000
12. [IDOR in the https://market.semrush.com/](https://hackerone.com/reports/837400) to Semrush - 155 upvotes, $0
13. [IDOR leads to Edit Anyone's Blogs / Websites](https://hackerone.com/reports/974222) to Automattic - 144 upvotes, $0
14. [[api.pandao.ru] IDOR for order delivery address](https://hackerone.com/reports/723461) to Mail.ru - 120 upvotes, $3000
15. [IDOR vulnerability (Price manipulation)](https://hackerone.com/reports/1403176) to Acronis - 119 upvotes, $0
16. [Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability](https://hackerone.com/reports/1658418) to Reddit - 115 upvotes, $5000
17. [IDOR and statistics leakage in Orders ](https://hackerone.com/reports/544329) to X (Formerly Twitter) - 110 upvotes, $289
18. [IDOR in https://3d.cs.money/](https://hackerone.com/reports/990878) to CS Money - 110 upvotes, $0
19. [IDOR leading to downloading of any attachment](https://hackerone.com/reports/668439) to BCM Messenger - 105 upvotes, $0
20. [IDOR leads to leak analytics of any restaurant](https://hackerone.com/reports/1116387) to Uber - 103 upvotes, $2000