# Review

* [ ] Some applications have an option where verified reviews are marked with some tick or it’s mentioned. Try to see if you can post a review as a **Verified Reviewer without purchasing that product**.
* [ ] Some app provides you with an option to provide a rating on a scale of 1 to 5, try to go beyond/below the scale-like **provide 0 or 6 or -ve**.
* [ ] Try to see if the same user can post multiple **ratings for a product**. This is an interesting endpoint to check for **Race Conditions**.
* [ ] Try to see if the file **upload field** is allowing any exts, it’s often observed that the devs miss out on implementing protections on such endpoints.
* [ ] Try to post reviews like some other users.
* [ ] Try **performing CSRF** on this functionality, often is not protected by tokens

> **Rating Feature Abuse**

*   [ ] Get Better Yearly Rates

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
