## Intro

API6:2023 Unrestricted Access to Sensitive Business Flows represents the risk of an attacker being able to identify and exploit API-driven workflows. If vulnerable an attacker will be able to leverage an organization's API request structure to obstruct other users. This obstruction could come in the form of spamming other users, depleting the stock of highly sought-after items, or preventing other users from using expected application functionality. This is a new addition to the 2023 top ten list.

## [OWASP Attack Vector Description](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

_Exploitation usually involves understanding the business model backed by the API, finding sensitive business flows, and automating access to these flows, causing harm to the business._

## [OWASP Security Weakness Description](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

_Lack of a holistic view of the API in order to fully support business requirements tends to contribute to the prevalence of this issue. Attackers manually identify what resources (e.g. endpoints) are involved in the target workflow and how they work together. If mitigation mechanisms are already in place, attackers need to find a way to bypass them._

## [OWASP Impacts Description](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

_In general technical impact is not expected. Exploitation might hurt the business in different ways, for example: prevent legitimate users from purchasing a product, or lead to inflation in the internal economy of a game._

## Summary

Regarding APIs, a flow is a series of requests and responses that lead to an operation. If, for example, a purchase flow for a web application does not restrict access to a purchase process then a scalper could automate requests to instantly drain the stock of an item down to nothing. This is where mechanisms like a Completely Automated Public Turing test to tell Computers and Humans Apart or CAPTCHA comes into play. If a flow has a CAPTCHA mechanism that requires human interaction then the automated requests could be interrupted and slow down automated purchasing.

![Screen Shot 2022-04-14 at 2.30.14 PM](https://www.gravwell.io/hs-fs/hubfs/Screen%20Shot%202022-04-14%20at%202.30.14%20PM.png?width=2296&name=Screen%20Shot%202022-04-14%20at%202.30.14%20PM.png)

_[Source](https://www.gravwell.io/blog/flows-best-buy-api-help-get-sony-ps5): Using Gravwell Flows and the Best Buy API to Help Obtain a Sony PlayStation 5._

Customers competing to purchase the PS5 would use API flows to either complete purchases as soon as new stock was available or alert upon stock updates. In the example above, an API flow has been created to automatically check for stock updates and send out an email alert.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

_The mitigation planning should be done in two layers:_

- _Business - identify the business flows that might harm the business if they are excessively used._
- _Engineering - choose the right protection mechanisms to mitigate the business risk._

_Some of the protection mechanisms are more simple while others are more difficult to implement. The following methods are used to slow down automated threats:_

- _Device fingerprinting: denying service to unexpected client devices (e.g headless browsers) tends to make threat actors use more sophisticated solutions, thus more costly for them_
- _Human detection: using either captcha or more advanced biometric solutions (e.g. typing patterns)_
- _Non-human patterns: analyze the user flow to detect non-human patterns (e.g. the user accessed the "add to cart" and "complete purchase" functions in less than one second)_
- _Consider blocking IP addresses of Tor exit nodes and well-known proxies_

_Secure and limit access to APIs that are consumed directly by machines (such as developer and B2B APIs). They tend to be an easy target for attackers because they often don't implement all the required protection mechanisms._

## Additional Resources

- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [API10:2019 Insufficient Logging & Monitoring](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xaa-insufficient-logging-monitoring.md)