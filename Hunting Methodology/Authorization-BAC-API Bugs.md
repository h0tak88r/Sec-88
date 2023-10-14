---
tags:
  - hunting-methodology
---
>**Test for BOLA**
- [ ] Use <span style="color:#06ea6c">account-A</span>'s Cookie/ Authorization-token to access <span style="color:#06ea6c">account-B</span>'s Resources/Objects
- [ ]  Use the newsletter unsubscribe Session to Access any <span style="color:#ff0000">Victim's</span> <span style="color:#ff0000">PII</span>
- [ ] Use The non-confirmed email session to access any of resources that demands Confirmed user
- [ ] 
 
>**Play with Request / Response**
- [ ]  Understand the pattern [ Sequential | Encoded |  UUID (aka GUID) | Other ]
- [ ] Change -> Next/Previous value -> Compute/Predict -> Data Type [string->number] -> Method [GET/POST]
- [ ] Duplicate -> `?id=1&id=2`
- [ ] Add as an array -> `?id[]=1&id[]=2`
- [ ] Wildcard -> `GET /users/id -> GET /users/*`
- [ ] Cross-deployments IDs -> Identify other deployments (hosts) of your target API
- [ ] UUID Hacking -> [tool](https://gist.github.com/DanaEpp/8c6803e542f094da5c4079622f9b4d18) [read more](https://danaepp.com/attacking-predictable-guids-when-hacking-apis) 

>**Excessive Data Exposure**
- [ ] Check if the API returns full data objects from database with sensitive data
- [ ] Compare client data with the API response to check if the filtering is done by client side
- [ ] Sniff the traffic to check for sensitive data returned by the API
- [ ] 

>**Broken Function Level Authorization**
- [ ] Can a regular user access administrative endpoints?
- [ ]  Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH) will allow level escalation?
- [ ] Enumerate/Bruteforce endpoints for getting unauthorized requests
- [ ] Check for Forbidden Features for low privilege user and try to use this features

>==**Mass Assignment**==

1. Enumerate object properties
- [ ]  API documentation
- [ ] Exercise data retrieval endpoints -> `watch-out for ?include=user.addresses,user.cards-like parameters `
- [ ] Uncover hidden properties 
- [ ] Guessing, based on API context
- [ ] Reverse engineering available API clients
- [ ] Use param-miner tool OR [Arjun](https://github.com/s0md3v/Arjun) to guess parameters

>**Improper Assets Management**

- [ ] Check for the API documentation
- [ ] Hosts inventory is missing or outdated
- [ ] Integrated services inventory, either first- or third-party, is missing or outdated
- [ ] Old or previous API versions are running unpatched