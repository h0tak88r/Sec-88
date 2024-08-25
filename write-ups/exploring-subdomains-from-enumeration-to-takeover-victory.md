---
description: >-
  If you enjoy what I do, please support me  Buy Me Ko-fi!
  https://ko-fi.com/h0tak88r
---

# Exploring Subdomains: From Enumeration to Takeover Victory

> **In the name of ALLAH the most gracious the most merciful**

So today i will talk about how i got my critical subdomain takeover on ford motors

> _Ford_ is a family _company_, one that spans the globe and has shared ideals. We value service to each other and the world as much as to our customers. Generations ...

### Choose target

<figure><img src="../.gitbook/assets/image (182).png" alt=""><figcaption><p>our target is ford.com domain</p></figcaption></figure>

### Subdomain enumeration

First i collected subdomains using subfalcon

```bash
# Tool link: https://github.com/h0tak88r/subfalcon
go install github.com/h0tak88r/subfalcon/cmd/subfalcon@latest

# Usage
subfalcon -l domains.txt
# Results saved to subfalconResults.txt
```

<figure><img src="../.gitbook/assets/Screenshot from 2024-03-21 04-35-10.png" alt=""><figcaption></figcaption></figure>

### Subdomain Takeover checking

So here i used my another go tool subov88r

```bash
# Tool Link 
https://github.com/h0tak88r/subov88r
# Install
go install github.com/h0tak88r/subov88r@latest
# passing subfalcon results to subov88r
subov88r -f subfalconResults.txt
```

The results was something like

<figure><img src="../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

the result that talk my attention was like

```bash
[ www.<subdomain>.ford.com, <subdomain>.trafficmanager.com, NXDOMAIN] Possiply Vulnerable to subdomain takeover vulnerability
```

So i quickly started to look into this subdomain but the `httpx` tool didn't recognize this subdomain as a valid domain

Then i decided to see this subdomain in the browser and as i expected\\

<figure><img src="../.gitbook/assets/image (194).png" alt=""><figcaption><p>Message that the subdomain may not be valid</p></figcaption></figure>

Ok let's check can i take over xyz project

[https://github.com/EdOverflow/can-i-take-over-xyz/issues/35](https://github.com/EdOverflow/can-i-take-over-xyz/issues/35)\
Oh no they say that it is not vulnerable

<figure><img src="../.gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

Still, I didn't give up. I decided to investigate on my own, and guess what? I found out that there was indeed an issue, and I successfully took control of it. It's always good to double-check! 🛡️🌐

Undeterred, I decided to manually investigate, and voila! Success – I managed to take over the CNAME `<vulnerable>.trafficmanager.com` . Always good to verify! 🛡️🌐

<figure><img src="../.gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

Then reported the issue with HIGHT severity and the Team changed the severity to Critical and triaged my report\
Update: Issue Resolved !!

<figure><img src="../.gitbook/assets/Screenshot from 2024-03-21 21-46-05.png" alt=""><figcaption></figcaption></figure>
