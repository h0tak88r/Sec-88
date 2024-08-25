# Unchecked Privileges: The Hidden Risk of Role Escalation in Collaborative Platforms

During a recent penetration testing engagement at CyberAR, we uncovered a seemingly simple yet critically impactful vulnerability in a platform designed to sync WhatsApp with CRM systems. This platform allows teams to collaborate within workspaces, manage members, and work on projects together. The feature is central to the platform's core business logic, making it an ideal target for thorough security testing. What we discovered was a privilege escalation flaw that allowed us to elevate a member’s permissions to admin, ultimately leading to a full takeover of a workspace.

***

### &#x20;**The Initial Discovery: Member Management Endpoint**

Our first step involved exploring the platform as a regular user with member-level permissions. We navigated to the member management page at [https://app.target.com/settings/members](https://app.target.com/settings/members), where we noticed something intriguing. The platform’s functionality heavily relied on REST API requests, and one request, in particular, caught our attention:

Invite member  request:

```http
POST /v2/workspace/{WORKSPACE-ID}/users
Host: api.target.com
Cookie: <Member's cookie>
Authorization: Bearer <Member's-JWT>

{
  "role": "MEMBER"
}
```

Given the critical nature of member management in collaborative platforms, we suspected that access control might be a weak point. Typically, developers focus on front-end validations but may overlook the need for strict access control at the API level. With this in mind, we decided to test whether a member could elevate their privileges by modifying the role in an invitation request.

### **Privilege Escalation to Admin**

To our surprise, when we modified the role to "ADMIN" in the request while still authenticated as a regular member, the server accepted it without any complaints. The request looked like this:

```http
POST /v2/workspace/{WORKSPACE-ID}/users
Host: api.target.com
Cookie: <Member's cookie>
Authorization: Bearer <Member's-JWT>

{
  "role": "ADMIN"
}
```

And it worked! The member now had admin privileges. This success led us to wonder if we could take this further and fully exploit this vulnerability.

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

#### **Exploiting the Vulnerability: Full Workspace Takeover**

The next logical step was to see if we could manipulate the member's role directly through the API. Normally, role modification should be restricted to admins or workspace owners, but we suspected that server-side validation might be missing. So, we crafted the following request as a member:

```http
PATCH /v2/workspaces/{Workspace-UUID}/users/{Member-User-UUID}
Host: api.target.com
Cookie: <member-session-cookie>
Authorization: Bearer <Member's-JWT>

{
  "role": "ADMIN"
}
```

This request was accepted by the server, effectively elevating our account to an admin role. Now, we had full control over the workspace.

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

### **How Attackers Could Obtain Necessary IDs**

A key question in exploiting this vulnerability was how an attacker could obtain the necessary workspace and user UUIDs. The answer was straightforward: another unprotected API endpoint provided all the required information. By simply sending a GET request, a member could retrieve the UUIDs of all users in the workspace:

```http
GET /v2/workspaces/{Workspace-UUID}/users
Host: api.target.com
Authorization: Bearer <Mwmber's-JWT>
```

With this information, the attacker could escalate their privileges to admin with ease.

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

### **Taking It Further: Removing the Original Admin**

Now that we had admin privileges, we wondered if we could remove the original workspace owner entirely. We attempted to delete the owner’s account from the workspace, example request:

```http
DELETE /v2/workspaces/{Workspace-UUID}/users/{Owner-User-UUID}
Host: api.target.om
Cookie: <admin-session-cookie>
Authorization: Bearer <Admin's-JWT>
```

Amazingly, the request succeeded, and we were now the sole admin of the workspace, having completely taken over the workspace from its original owner.

### **Recommendations**

* **Strict Access Control:** Ensure that API endpoints, especially those handling roles and permissions, are protected by server-side access control mechanisms.
* **UUID Protection:** Avoid exposing critical IDs in API responses. Consider using role-based access to ensure only authorized users can access sensitive information.
* **Thorough Testing:** Perform comprehensive security testing, particularly on features that involve user roles, permissions, and collaboration.

This vulnerability underscores the importance of robust access control in multi-user platforms. Even a simple oversight can lead to complete system compromise. Always think critically, test thoroughly, and secure your endpoints.

### **Conclusion**

This vulnerability allowed us to escalate our privileges from a member to an admin, ultimately taking over an entire workspace. The issues we discovered stemmed from a lack of proper access control at the API level and exposed UUIDs that made exploitation straightforward.

### Resources

{% embed url="https://purplesec.us/learn/privilege-escalation-attacks/" %}

{% embed url="https://www.keepersecurity.com/blog/2024/04/15/six-ways-to-prevent-privilege-escalation-attacks/" %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation" %}

{% embed url="https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" %}
