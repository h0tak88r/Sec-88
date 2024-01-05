---
description: Premium...........Paywall Bypass....refund....etc
---

# Money-Related Features

## **Premium Feature Abuse**

* [ ] Try **forcefully browsing** the areas or some particular endpoints which come under premium accounts
* [ ] **Pay for a premium feature** and cancel your subscription. If you get a **refund** but the feature is still **usable**, it’s a monetary impact issue.
* [ ] Some applications use **true-false request/response values** to validate if a user is having access to premium features or not.
* [ ] Try using **Burp’s Match & Replace to see if you** can replace these values whenever you browse the app & access the premium features.
* [ ] Always check **cookies or local storage** to see if any variable is checking if the user should have access to premium features or not.

> **Refund Feature Abuse**

* [ ] Purchase a product (usually some subscription) and ask for a refund to see if the feature is still accessible.
* [ ] Try for currency arbitrage
* [ ] Try making multiple requests for subscription cancellation (race conditions) to see if you can get multiple refunds.

## **Cart/Wish list Abuse**

* [ ] Add a product in **negative quantity** with other products in positive quantity to balance the amount.
* [ ] Add a product in more than the available quantity.
* [ ] Try to see when you add a product to your Wish-list and move it to a cart if it is possible to move it to some other user’s cart or delete it from there.

## **Orders Page**

* [ ] IDOR

```python
    <https://example.com/account/orders/12345>
    GET /account.php?history=y&orderno=10425128 HTTP/2
    <https://example.com/pdf/><orderno>.pdf.
    <https://example.com/pdf/10425128.pdf>
```

* [ ] Leaking Credit Card Details in Responses

```python
	I was testing a CRM (Customer Relationship Management) application, in which help desk representatives were only able to view basic customer details: their first and last names, their location, and the last 4 digits of their credit card number. But when I inspected the response, I found that the developers returned extra information that was not visible in the application view:
    
    HTTP/1.1 200 OK
    Host: vulnlab.com
    {“first_name”: “Harry”, “last_name”: “Potter”, “isAdmin”: false, “location”:
    “London”, “last_bill_cycle”: “110219”, “mask_cc”: “******4510”, “exp_-
    date”: “08/23”, “cvv”: “123”, “full_card”: “6011111111114510”}
```

* [ ] Previously made orders with victim's email leading to Order History and PII leaks

```python
Here's what to look for:
1. Target app that permits guest orders without creating an account
2. Target app doesn't require email verification for new account creation, or you've found an email verification bypass on sign-up
- Steps to reproduce 
1. Place an order on the site as a "Guest" and use the victim's email during checkout, e.g., victim@example.com
2. The victim receives an email with the receipt
3. As an attacker, sign up using the email victim@example.com assuming there's no email verification
4. Navigate to the account's order history page, and you might strike gold by finding the previously made orders, leading to Order History and PII leaks
```

## **Transfer Money**

* [ ] Bypass Transfer Money Limit

```python
use negative number to exceed money transfer limit  
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

*   [ ] Borrow Money Without Return

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

## **Gifts Feature**

* [ ] [**Race Condition allows to redeem multiple times gift cards which leads to free "money"**](https://hackerone.com/reports/759247)
* [ ] [**Race conditions can be used to bypass invitation limit**](https://hackerone.com/reports/115007)

## **Discount Checkout Flaws**

* [ ] Apply the **same code** more than once to see if the coupon code is reusable.
* [ ] Input the gift code and intercept the request and remove it from the request
* [ ] Manipulate the response when reuse the discount code
* [ ] Discount is for multiple Items ? collect items and intercept the request change it to one item
* [ ] No Rate Limit --> https://hackerone.com/reports/123091
* [ ] Race Condition--> https://hackerone.com/reports/157996
* [ ] Try Mass Assignment or **HTTP Parameter Pollution** to see if you can add multiple coupon codes while the application only accepts one code from the Client Side.
* [ ] Try performing attacks that are caused by missing input sanitization such as **XSS, SQLi**, etc. on this field
* [ ] Try adding discount codes on the products which **are not covered under discounted** items by tampering with the request on the server-side.

> **Purchasing Feature Abuse**

* [ ] Buy Products at lower price • Add cheap items to the cart. During the payment process, capture the encrypted payment data being sent to the payment gateway. • Initiate another shopping process and add expensive/multiple items to the cart. Replace the payment data with the previously captured data. • If the application does not cross-validate the data, we’ll be able to buy products at a lower price
* [ ] **IDOR** in Change Price
  1. make a request to buy anything
  2. try changing the price in request/response
* [ ] **Currency Arbitrage**
  * Pay in 1 currency say USD and try to get a refund in EUR. Due to the diff in conversion rates, it might be possible to gain more amount.
  * change USD to any poor currency

## **Delivery Charges Abuse**

* [ ] Try tampering with the delivery charge rates to -ve values to see if the final amount can be reduced.
* [ ] Try checking for the free delivery by tampering with the params.
