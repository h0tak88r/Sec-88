---
tags:
  - hunting-methodology
---
tag:#Google-DorkingTest for [[API Security/OWASP TOP 10/Broken Object Level Authorization (BOLA)|Broken Object Level Authorization (BOLA)]]
# Authorization Testing Strategy
>**BOLA**
1. Create a `UserA` account.
2. Use the API and discover requests that involve resource IDs as `UserA`.
3. Document requests that include resource IDs and should require authorization.
4. Create a `UserB` account.
5. Obtaining a valid `UserB` token and attempt to access `UserA`'s resources.
6. OR Pass `userA` authorization token to `Auth-Analyzer/Autorize` Extensions 
7. Repeat every request you make with `userB` account with `userA` authorization token
----
Play with Request and Response
1. Understand the pattern
	- Sequential
	- Encoded
	- UUID (aka GUID)
	- Other
1. Tamper 
	- Change -> Next/Previous value -> Compute/Predict -> Data Type [string->number] -> Method [GET/POST]
	- Duplicate -> `?id=1&id=2`
	- Add as an array -> `?id[]=1&id[]=2`
	- Wildcard -> `GET /users/id -> GET /users/*`
	- cross-deployments IDs -> Identify other deployments (hosts) of your target API
	- UUID Hacking -> [tool](https://gist.github.com/DanaEpp/8c6803e542f094da5c4079622f9b4d18) [read more](https://danaepp.com/attacking-predictable-guids-when-hacking-apis) 
----
>**Excessive Data Exposure**
1. Check if the API returns full data objects from database with sensitive data
2. Compare client data with the API response to check if the filtering is done by client side
3. Sniff the traffic to check for sensitive data returned by the API
---
>**Broken Function Level Authorization**
1. Can a regular user access administrative endpoints?
2. Testing different HTTP methods (GET, POST, PUT, DELETE, PATCH) will allow level escalation?
3. Enumerate/Bruteforce endpoints for getting unauthorized requests
4. Check for Forbidden Features for low privilege user and try to use this features
---
>**Mass Assignment**
1. Enumerate object properties
	-  API documentation
	- Exercise data retrieval endpoints -> `watch-out for ?include=user.addresses,user.cards-like parameters `
	- Uncover hidden properties 
		- Guessing, based on API context
		- Reverse engineering available API clients
	- Use param-miner tool OR [Arjun](https://github.com/s0md3v/Arjun) to guess parameters
---
>**Improper Assets Management**
- Check for the API documentation
- Hosts inventory is missing or outdated
- Integrated services inventory, either first- or third-party, is missing or outdated
- Old or previous API versions are running unpatched
