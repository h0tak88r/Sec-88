- ==#====**Insecure deserialization**==
    
    - **Insecure Deserialization**
        
        - **`Insecure deserialization`** is a security vulnerability that occurs when an application blindly **`deserializes`** **untrusted** data without **validating** it first. `**Deserialization**` is the process of **converting serialized data** into its **original form**. `**Serialized**` data is typically in the **form** of a string or a stream of bytes, and it can be used to **transfer data** between different systems or **store** it for later use.
        - When an application receives **serialized data** from an **untrusted source**, such as a **user input field** or an **external file**, it should first **validate** the data to ensure that it conforms to the expected format and does not contain any **malicious code**. However, if the application blindly **`deserializes`** the data without validating it first, an attacker can exploit this vulnerability by crafting a malicious payload that, when **`deserialized`**, can execute arbitrary code on the server or client-side.
        - For example, an attacker can modify a serialized object's properties to inject malicious code that gets executed when the object is **`deserialized`**. This can lead to a range of **security issues**, including **data theft**, **privilege escalation**, and **remote code execution**.
        - To **prevent insecure deserialization** vulnerabilities, applications should implement strict input validation and use a secure **deserialization library** that can detect and reject malicious payloads. Additionally, applications should avoid **`deserializing`** **untrusted data** whenever possible and use alternative data formats, such as JSON, which are less prone to such
        
    - **How to identify insecure deserialization [PHP]**
        
        When serialized, this object may look something like this:
        
        ```
        O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
        ```
        
        This can be interpreted as follows:
        
        - `O:4:"User"` - An object with the 4-character class name `"User"`
        - `2` - the object has 2 attributes
        - `s:4:"name"` - The key of the first attribute is the 4-character string `"name"`
        - `s:6:"carlos"` - The value of the first attribute is the 6-character string `"carlos"`
        - `s:10:"isLoggedIn"` - The key of the second attribute is the 10-character string `"isLoggedIn"`
        - `b:1` - The value of the second attribute is the boolean value `true`
        
        ### **Java serialization format**
        
        Some languages, such as Java, use binary serialization formats. This is more difficult to read, but you can still identify serialized data if you know how to recognize a few tell-tale signs. For example, serialized Java objects always begin with the same bytes, which are encoded as `ac ed` in hexadecimal and `rO0` in Base64.
        
        Any class that implements the interface `java.io.Serializable` can be serialized and `deserialized`. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and `deserialize` data from an `InputStream`.
        
    - **change** `**boolean**` **value value to true (**`**b:1**`**) from false (**`**b:0**`**)**
    - [**Modifying serialized data types**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
        
        1. In Burp Repeater, use the Inspector panel to modify the session cookie as follows:
            
            `O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}`
            
            - Update the length of the `username` attribute to `13`.
            - Change the username to `administrator`.
            - Change the access token to the integer `0`. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
            - Update the data type label for the access token by replacing `s` with `i`.
        
    - [**Using application functionality to exploit insecure deserialization**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)
        
        - delete your account by sending a `POST` request to `/my-account/delete`.
        - In Burp Repeater, study the session cookie using the Inspector panel. Notice that the serialized object has an `avatar_link` attribute, which contains the file path to your avatar.
        - Edit the serialized data so that the `avatar_link` points to `/home/carlos/morale.txt`.  
            `s:11:"avatar_link";s:23:"/home/carlos/morale.txt"`
        - Change the request line to `POST /my-account/delete` and send the request. Your account will be **deleted**, along with **Carlos's morale.txt file.**
        
    - [**Arbitrary object injection in PHP**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
        
        - notice that the website references the file `/libs/CustomTemplate.php`
        - notice that you can read the source code by appending a tilde (`~`) to the filename
        - notice the `CustomTemplate`class contains the `__destruct()`magic method.
        - This will invoke the `unlink()`method on the `lock_file_path`attribute, which will delete the file on this path.
        - `O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}`
        - Base64 and URL-encode this object and save it to your clipboard.
        - Send the request. The `__destruct()` magic method is automatically invoked and will delete Carlos's file.
        
    - [**Arbitrary object injection in PHP**](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
        
        notice that the website references the file `/libs/CustomTemplate.php`
        
        notice that you can read the source code by appending a tilde (`~`)
        
        notice the `CustomTemplate`class contains the `__destruct()`magic method. This will invoke the `unlink()`method on the `lock_file_path` attribute, which will delete the file on this path.
        
        ```
        O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
        ```
        
        The final object should look like this:
        
        1. Base64 and URL-encode this object and save it to your clipboard.
        
        In Burp Repeater, replace the session cookie with the modified one in your clipboard.
        
    
- ==**\#JWT Security**==
    
    - [ ] change role
    - [ ] remove signature