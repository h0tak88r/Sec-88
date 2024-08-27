# IDOR

## **Understanding Insecure Direct Object References (IDOR)**

#### **What is IDOR?**

Insecure Direct Object References (IDOR) occur when an application uses user-supplied input to access objects directly without proper access control checks. This vulnerability can lead to unauthorized access to data or functions, enabling attacks such as horizontal and vertical privilege escalation.

#### **How IDOR Occurs**

IDOR vulnerabilities typically arise when the application fails to verify if a user is authorized to access or manipulate an object. These vulnerabilities are most commonly associated with horizontal privilege escalation (accessing data of other users at the same privilege level) but can also involve vertical privilege escalation (accessing data or functions reserved for higher privilege levels).

***

## **Common Examples of IDOR**

#### **1. IDOR with Direct Reference to Database Objects**

**Scenario:** A URL that directly references a customer account number:

```
https://insecure-website.com/customer_account?customer_number=132355
```

**Vulnerability:** An attacker can change the `customer_number` parameter to access another user's account, leading to unauthorized access.

**2. IDOR with Direct Reference to Static Files**

**Scenario:** A URL that directly references a file stored on the server:

```
https://insecure-website.com/static/12144.txt
```

**Vulnerability:** An attacker can modify the file name to access other users' files, potentially revealing sensitive information.

#### **3. IDOR in POST Body**

**Scenario:** A form that includes a hidden field with a user ID:

```html
<form action="/update_profile" method="post">
  <input type="hidden" name="user_id" value="12345">
  <button type="submit">Update Profile</button>
</form>
```

**Vulnerability:** If proper access controls are not in place, an attacker can manipulate the `user_id` field to update another user's profile.

***

## Vulnerable Code Examples

#### **1. PHP Example**

**Scenario:** An application retrieves user profile information based on a user ID passed as a GET parameter.

**Vulnerable Code:**

```php
<?php
// Vulnerable code: No access control check
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $query);
$user = mysqli_fetch_assoc($result);

// Display user information
echo "Username: " . $user['username'] . "<br>";
echo "Email: " . $user['email'] . "<br>";
?>
```

**Explanation:**

* The application directly uses the `user_id` parameter from the URL to retrieve user information.
* An attacker can modify the `user_id` parameter to access the profiles of other users.

***

#### **2. JavaScript/Node.js Example**

**Scenario:** A Node.js application allows users to view their account details by passing a user ID in the URL.

**Vulnerable Code:**

```javascript
// Vulnerable code: No access control check
app.get('/user/:id', (req, res) => {
  const user = db.users.find(user => user.id === req.params.id);
  res.json(user);
});
```

**Explanation:**

* The application directly accesses the user data based on the `id` parameter from the URL.
* An attacker can change the `id` in the URL to access the details of other users.

***

#### **3. Python/Flask Example**

**Scenario:** A Flask application retrieves user information based on a user ID passed in the URL.

**Vulnerable Code:**

```python
# Vulnerable code: No access control check
@app.route('/user/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.serialize())
```

**Explanation:**

* The application retrieves user data directly based on the `user_id` from the URL.
* An attacker can modify the `user_id` in the URL to access the data of other users.

***

#### **4. Ruby on Rails Example**

**Scenario:** A Rails application allows users to access project details by passing a project ID in the URL.

**Vulnerable Code:**

```ruby
# Vulnerable code: No access control check
def show
  @project = Project.find(params[:id])
  render json: @project
end
```

**Explanation:**

* The application retrieves project data directly based on the `id` parameter from the URL.
* An attacker can modify the `id` to access details of projects they don't own.

***

#### **5. Java Example (JSP/Servlet)**

**Scenario:** A Java web application retrieves order details based on an order ID passed as a request parameter.

**Vulnerable Code:**

```java
// Vulnerable code: No access control check
String orderId = request.getParameter("order_id");
Order order = orderService.getOrderById(orderId);
request.setAttribute("order", order);
request.getRequestDispatcher("/orderDetails.jsp").forward(request, response);
```

**Explanation:**

* The application retrieves order data based on the `order_id` parameter from the request.
* An attacker can modify the `order_id` to access the details of other users' orders.

***

#### **6. C#/.NET Example (ASP.NET MVC)**

**Scenario:** An ASP.NET MVC application allows users to view their orders by passing an order ID in the query string.

**Vulnerable Code:**

```csharp
// Vulnerable code: No access control check
public ActionResult ViewOrder(int orderId)
{
    var order = db.Orders.Find(orderId);
    return View(order);
}
```

**Explanation:**

* The application directly uses the `orderId` parameter to retrieve order information.
* An attacker can modify the `orderId` in the query string to view orders belonging to other users.

***

## **Checklist for Testing IDOR Vulnerabilities**

#### **1. Identify User-Controlled Parameters**

* Review URLs, POST bodies, headers, and cookies for parameters that reference objects (e.g., `user_id`, `file_id`, etc.).
* Look for identifiers exposed in client-side code or API responses.

#### **2. Test Parameter Manipulation**

* Attempt to change the parameter value to that of another user’s ID or object reference.
* Observe if unauthorized data or functions are exposed.

#### **3. Examine API Endpoints**

* Review RESTful API endpoints for object references in URLs or request bodies.
* Test different object IDs in API requests to see if unauthorized data is returned.

#### **4. Test with Different User Roles**

* Use accounts with different privilege levels (e.g., admin, regular user, guest) to test if object references can be used to escalate privileges.\`\`

{% hint style="info" %}
**Pro Tip:**

1. **Identify Authentication Methods:** Make sure to capture the session cookie, authorization header, or any other form of authentication used in requests.
2. **Use Auth-Analyzer in Burp Suite:** Pass these authentication tokens to the Auth-Analyzer Burp extension. This tool will replay all requests with the captured session information.
3. **Test with Another User:** Log in as a different user and activate the Auth-Analyzer extension. If you see the `SAME` tag in the extension results, this could indicate an IDOR vulnerability.
4. **Manual Verification:** Always manually check the request to confirm whether the vulnerability is genuine.
5. **Assess ID Predictability:** Determine if the IDs are predictable. If they aren't, investigate where they might be leaked, such as in other API responses. This could help in further exploitation or verification of the vulnerability.
{% endhint %}

***

## **Code Examples for Prevention**

#### **1. PHP Example**

```php
// Incorrect (Vulnerable)
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $query);

// Correct (Secure)
session_start();
$current_user_id = $_SESSION['user_id'];
$query = "SELECT * FROM users WHERE id = $current_user_id";
$result = mysqli_query($conn, $query);
```

#### **2. JavaScript/Node.js Example**

```javascript
// Incorrect (Vulnerable)
app.get('/user/:id', (req, res) => {
  const user = db.users.find(req.params.id);
  res.send(user);
});

// Correct (Secure)
app.get('/user/:id', (req, res) => {
  const user = db.users.find(req.params.id);
  if (user.id !== req.session.userId) {
    return res.status(403).send('Access Denied');
  }
  res.send(user);
});
```

#### **3. Python/Flask Example**

```python
# Incorrect (Vulnerable)
@app.route('/user/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.serialize())

# Correct (Secure)
@app.route('/user/<int:user_id>')
def get_user(user_id):
    if user_id != current_user.id:
        return jsonify({"error": "Access Denied"}), 403
    user = User.query.get(user_id)
    return jsonify(user.serialize())
```

***

### **Prevention Techniques**

#### **1. Implement Access Control Checks**

* Always verify that the user is authorized to access or modify the object.

#### **2. Avoid Exposing Identifiers in URLs**

* Use session or JWT tokens to determine the current user instead of relying on user-controlled parameters.
