# Firebase Test Cases

<details>

<summary><strong>Signup Misconfigurations</strong></summary>

**Test Firebase Identity Toolkit**

{% code overflow="wrap" %}
```bash
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyCpGNhMyM9-xMnITdD0uGSQOq2GbSrG8M0" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@target.com","password":"test","returnSecureToken":true}'
```
{% endcode %}

**Test anonymous signup**

{% code overflow="wrap" %}
```bash
curl -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyCpGNhMyM9-xMnITdD0uGSQOq2GbSrG8M0" \
  -H "Content-Type: application/json" \
  -d '{}'
```
{% endcode %}



</details>

<details>

<summary><strong>Firebase Cloud Messaging</strong></summary>

{% code overflow="wrap" %}
```bash
curl -s -X POST --header "Authorization: key=AI..." --header "Content-Type:application/json" 'https://fcm.googleapis.com/fcm/send' -d '{"registration_ids":["1"]}'
```
{% endcode %}

</details>

<details>

<summary><strong>Test API Key Restrictions (Referrer Bypass)</strong></summary>

{% code overflow="wrap" %}
```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}' \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY"
```
{% endcode %}

</details>

<details>

<summary><strong>Test Realtime Database Rules (Unauthenticated Read)</strong></summary>

{% code overflow="wrap" %}
```bash
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents?key=$API_KEY"
```
{% endcode %}

</details>

<details>

<summary><strong>Test Multi-Tenant Identity Abuse</strong></summary>

{% code overflow="wrap" %}
```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"tenantId":"'$TENANT_ID'","returnSecureToken":true}' \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY"
```
{% endcode %}

</details>

*



