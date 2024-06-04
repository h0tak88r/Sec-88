# Login Backdoor

* Back to jadx in the DoLogin Activity i found this weird Code

<figure><img src="../../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

The "devadmin" part in the `postData` method handles a specific case where the username is "devadmin." When the username is "devadmin," the method sends the login data to a different endpoint (`/devlogin`) rather than the standard login endpoint (`/login`). This could be used for developers or administrators who might need to authenticate through a different process or endpoint. Here’s a more detailed explanation focusing on this aspect:

1. **Check Username:**
   *   The method checks if the username is "devadmin":

       ```java
       javaCopy codeif (DoLogin.this.username.equals("devadmin")) {
       ```
2. **Send to `/devlogin` Endpoint:**
   *   If the username is "devadmin", it sets the entity (the body of the HTTP request) for `httppost2` (which points to the `/devlogin` URL) with the prepared login data and executes this post request:

       ```java
       javaCopy codehttppost2.setEntity(new UrlEncodedFormEntity(nameValuePairs));
       responseBody = httpclient.execute(httppost2);
       ```
3. **Send to `/login` Endpoint:**
   *   If the username is not "devadmin", it sets the entity for `httppost` (which points to the standard `/login` URL) with the login data and executes this post request:

       ```java
       javaCopy codehttppost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
       responseBody = httpclient.execute(httppost);

       ```

* So Login with username "**devadmin**" and **without password** will authenticate you as devadmin
