---
tags:
  - web_hunting
---
- Some applications have an option where verified reviews are marked with some tick or it’s mentioned. Try to see if you can post a review as a **Verified Reviewer without purchasing that product**.
- Some app provides you with an option to provide a rating on a scale of 1 to 5, try to go beyond/below the scale-like **provide 0 or 6 or -ve**.
- Try to see if the same user can post multiple **ratings for a product**. This is an interesting endpoint to check for **Race Conditions**.
- Try to see if the file **upload field** is allowing any exts, it’s often observed that the devs miss out on implementing protections on such endpoints.
- Try to post reviews like some other users.
- Try **performing CSRF** on this functionality, often is not protected by tokens