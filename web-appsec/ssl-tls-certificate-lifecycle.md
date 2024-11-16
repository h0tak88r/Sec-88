# SSL/TLS Certificate Lifecycle

## **Understanding the SSL/TLS Certificate Lifecycle**

<figure><img src="../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

SSL/TLS certificates are crucial for secure online communication. They are issued by Certificate Authorities (CAs) and verify the identity of websites and servers. Each certificate has a lifecycle, starting with a request and ending with expiration or revocation.

## Stages

**1. Request and Enrollment**

* A user requests a certificate by submitting a Certificate Signing Request (CSR).
* The CSR contains information about the domain name or organization.
* The CA validates the request and issues the certificate.

**2. Issuance and Provisioning**

* The CA digitally signs the certificate, confirming its authenticity.
* The certificate is installed on the website or server.

**3. Usage and Monitoring**

* The certificate is used for secure communication.
* Monitoring systems track certificate usage and status.
* Timely renewal or revocation is ensured.

**4. Expiration and Renewal**

* Certificates expire after a certain period.
* Renewal is necessary to avoid interruptions.
* The certificate holder or CA initiates the renewal process.
* A new certificate is issued with a digital stamp.

**Effective certificate management is essential for maintaining secure online operations.**

## CRL

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

A certificate revocation list (CRL) is a list of [digital certificates](https://www.techtarget.com/searchsecurity/definition/digital-certificate) that have been revoked by the issuing certificate authority ([CA](https://www.techtarget.com/searchsecurity/definition/certificate-authority)) before their actual or assigned expiration date.

It is a type of blocklist that includes certificates that should no longer be trusted and is used by various endpoints, including [web browsers](https://www.techtarget.com/whatis/definition/browser), to verify if a certificate is valid and [trustworthy](https://searchcloudsecurity.techtarget.com/tip/Are-Amazon-certificate-authority-services-trustworthy).

The CRL file is signed by the CA to prevent tampering.

## OCSP

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (291).png" alt=""><figcaption></figcaption></figure>

The Online Certificate Status Protocol (OCSP) is an alternative to the certificate revocation list (CRL) and is used to check whether a digital certificate is valid or if it has been revoked.

The OCSP is an Internet Protocol (IP) that certificate authorities (CAs) use to determine the status of secure sockets layer/transport layer security (SSL/TLS) certificates, which are common applications of X.509 digital certificates. This helps web browsers check the status and validity of Hypertext Transfer Protocol Secure (HTTPS) websites.\


## HTTPS Workflow

<figure><img src="../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

**1. Client Generates a Symmetric Key:**

* The client creates a random symmetric key that will be used to encrypt and decrypt the actual data.

**2. Client Encrypts Key with Server's Public Key:**

* The client encrypts the symmetric key using the public key of the server, which is embedded in the server's SSL certificate.

**3. Server Decrypts Key with Private Key:**

* The server receives the encrypted symmetric key and decrypts it using its private key. This process ensures that only the server can access the symmetric key.

**4. Secure Channel Established:**

* Now that both the client and server have the same symmetric key, they can establish a secure, encrypted channel for communication.

**5. Data Exchange:**

* All subsequent data transmitted between the client and server is encrypted using the symmetric key. This ensures that the data remains confidential and protected from eavesdropping.

## References

{% embed url="https://www.fortinet.com/de/resources/cyberglossary/ocsp" %}

{% embed url="https://www.youtube.com/watch?v=CVFi9v2gmBk&list=PLDRMxi70CdSCnfKDKYGNhkZB0iq0QVJ8D&index=1" %}

{% embed url="https://www.sectigo.com/resource-library/the-evolving-ssl-tls-certificate-lifecycle-how-to-manage-the-changes#The%20SSL/TLS%20certificate%20lifecycle%20stages" %}
