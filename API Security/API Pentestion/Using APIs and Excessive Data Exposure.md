# API Documentation

Now that you know how to find live APIs and the relevant documentation, we will briefly review using an API as it was intended and how you can discover excessive data exposure. The next step in our API hacking process will be to use documentation to authenticate to the target API and begin forming requests.

Although API documentation is straightforward, there are a few elements to look out for. The overview is typically the first section of API documentation. Generally found at the beginning of the doc, it will provide a high-level introduction to how to connect and use the API. In addition, it could contain information about authentication and rate-limiting. 

Review the documentation for functionality, or the actions that you can take using the given API. These will be represented by a combination of an HTTP method (GET, PUT, POST, DELETE) and an endpoint. Every organization’s APIs will be different, but you can expect to find functionality related to user account management, options to upload and download data, different ways to request information, and so on. 

When making a request to an endpoint, make sure you note the request requirements. Requirements could include some form of authentication, parameters, path variables, headers, and information included in the body of the request. The API documentation should tell you what it requires of you and mention which part of the request that information belongs in. If the documentation provides examples, use them to help you. Typically, you can replace the example values with the ones you’re looking for. The table below describes some of the conventions often used in these examples. 

#### API Documentation Conventions

|   |   |   |
|---|---|---|
|Convention|Example|Meaning|
|: or {}|/user/:id<br><br>/user/{id}<br><br>/user/2727<br><br>/account/:username<br><br>/account/{username}<br><br>/account/scuttleph1sh|The colon or curly brackets are used by some APIs to indicate a path variable. In other words, “:id” represents the variable for an ID number and “{username}” represents the account username you are trying to access.|
|[]|/api/v1/user?find=[name]|Square brackets indicate that the input is optional.|
|\||“blue” \| “green” \| “red”|Double bars represent different possible values that can be used.|

Understanding documentation conventions will help you create well-formed requests and troubleshoot instances where the API doesn't respond as expected. To better understand API documentation, let's take the reverse-engineered crAPI Swagger specs and import this into Postman. Using the Swagger Editor (https://editor .swagger.io), import the crAPI Swagger file that we created in the previous module. In the crAPI Swagger specification, we can see there are several different paths for endpoints starting with /identity, /community, and /workshop.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/tvmP92upTSKuuzFbal4A_UsingAPI1.PNG)

Using the Swagger Editor allows us to have a visual representation of our target's API endpoints. By browsing through and expanding the requests you can see the endpoint, parameters, request body, and example responses. 

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/cajspgGBROmR18GBQaTz_UsingAPI2.PNG)

 The crAPI POST request above requires JSON values sent over the request body and the expectation is that those values will be in the form of a string. Reviewing documentation also gives us the opportunity to see the purpose of the various endpoints as well as some of the naming schemes used for data objects. Reviewing the documentation will lead you to interesting requests to target in your attacks. Even at this stage, you could discover potential vulnerabilities like Excessive Data Exposure.

# Editing Postman Collection Variables

When you start working with a new collection in Postman it is always a good idea to get a lay of the land, by checking out the collection variables. You can check on your Postman collection variables by using the collection editor.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/j96Inp9PR2mEM4Zz1I9L_UsingAPI8.PNG)

You can get to the collection editor by using your crAPI Swagger collection, selecting the three circles on the right side of a collection, and choosing "Edit". Selecting the Variables tab will show us that the variable "baseUrl" is used.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/YZWAKkLHTMySimU9EzyF_UsingAPI10.PNG)

Make sure that the baseUrl Current Value matches up with the URL to your target. If your target is localhost then it should match the image above. If your target is the ACE lab then the current value should be http://crapi.apisec.ai. Once you have updated a value in the editor, you will need to use the Save button found at the top right of Postman.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/qySSCGnSGJmbUtASYUpQ_UsingAPI11.PNG)

# Updating Postman Collection Authorization

In order to use Postman to make authorized API requests, we will need to add a valid token to our requests. This can be done for all of the requests within a collection by adding an authorization method to the collection. Using the Authorization tab, within the collection editor, we will need to select the right type for authorization. For crAPI, this will be a Bearer Token.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/asqDlJ4OR4qY9bg8ak1b_UsingAPI9.PNG)

Tokens are usually provided after a successful authentication attempt. For crAPI, we will be able to obtain a Bearer Token once we successfully authenticate with the POST request to /identity/api/auth/login. 

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/1XtUYT0FRJe0ZLeYI2aZ_UsingAPI12.PNG)

Navigate to the POST login request in your collection and update the values for "email" and "password" to match up with the account you created. If you don't remember, then you will need to go back and register for an account. Once you have successfully authenticated you should receive a response containing a Bearer token like the one seen above. 

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/PPWP8Yq8SqqPdjBEmK4h_UsingAPI13.PNG)

Copy the token found within the quotes and paste that value into the collection editor's authorization tab. Make sure to save the update to the collection. Now you should now be able to use the crAPI API as an authorized user and make successful requests using Postman.

## OWASP API 3: Excessive Data Exposure 

Excessive Data Exposure occurs when an API provider sends back a full data object, typically depending on the client to filter out the information that they need. From an attacker's perspective, the security issue here isn't that too much information is sent, instead, it is more about the sensitivity of the sent data. This vulnerability can be discovered as soon as you are able to start making requests. API requests of interest include user accounts, forum posts, social media posts, and information about groups (like company profiles).

Ingredients for excessive data exposure:

- A response that includes more information than what was requested
- Sensitive Information that can be leveraged in more complex attacks

If an API provider responds with an entire data object, then the first thing that could tip you off to excessive data exposure is simply the size of the response. 

**Request**
`GET /api/v1/user?=CloudStrife`

**Response**
```json
200 OK HTTP 1.1

--snip--

{"id": "5501",

"fname": "Cloud",

"lname": "Strife",

"privilege": "user",

"representative": [

     "name": "Don Coreneo",

     "id": "2203",

     "email": "dcorn@gmail.com",

     "privilege": "admin",

     "MFA": false   
     ]

}
```

In the response, we see that not only is the requested user's information provided but so is the data about the administrator who created the user's account. Including the administrator's information in a request like this is an example of excessive data exposure because it goes beyond what was requested and exposes sensitive information like the name, email, role, and multifactor status of the admin.

Now if we return to crAPI, let's look through the specification using the Swagger Editor to see if we can spot any potential interesting requests. Since we are looking for data that is returned to us our focus will be on the crAPI GET requests. The first of these requests listed in the crAPI Swagger docs is `GET /identity/api/v2/user/dashboard`. ![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/T1xPrikRYGXHldfjZ0ts_UsingAPI3.PNG)

The purpose of this request is to populate a user's dashboard. There is plenty of interesting information, but the information here is going to be specific to the requester, based on their access token. This does give us an idea of some of the object key naming schemes and potentially sensitive information to search for. Information like "id", "name", "email", "number", "available_credit", and "role" would all be interesting to discover about other users. So, we should look through other requests to see if any include any of these. 

If you think through the different types of endpoints (/identity, /community, and /workshop), consider which of these is likely to involve the information of other users. Community sounds like something that would involve other users, so let's check out an associated GET request.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/1Zyr5SxHSgq1IBYjv1J9_UsingAPI4.PNG)

This GET request is used to update the community forum. Check out some of the data that is returned:

 ![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/lkwPK1QOTuhy0sOGGoGT_UsingAPI5.PNG)

In this forum post, an "author" object with "nickname", "email", and "vehicleid" is returned. This could be interesting. Now, this is a great example to see what is visually represented in a web browser versus what exists within the API response behind the scenes.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/x385f6RkTTdgluIktSTi_UsingAPI6.PNG)

As you can see, none of the interesting sensitive information can be found in the community forum. However, if we intercept the API requests that populate the recent posts to the forum we will find that the provider is sending over a full data object depending on the client to filter out the sensitive information. Depending on the client to filter information will not stop us from being able to capture sensitive data.

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/site/2147573912/products/DM563qiCTrCUoZGtZa7X_UsingAPI7.PNG)

Using Burp Suite's Repeater for the GET request to /community/api/v2/community/posts/recent reveals all of the sensitive data we were hoping to find. This instance of Excessive Data Exposure reveals usernames, emails, IDs, and vehicle IDs all of which may prove handy in additional attacks. 

Now you should have a pretty good idea about how to start using an API as it was intended. It really helps to how an API will respond to failed and successful requests. Get an idea of the various functions intended by the API, so that you can better understand where to focus your attacking efforts. Remember that at this stage, you can already discover crucial vulnerabilities.