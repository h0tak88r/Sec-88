# My Methodlogy with Public BBP

## Target Selection

In the initial phase of my bug hunting journey on a renowned bug bounty platform, I navigated to the HackerOne platform to find a target with a substantial business presence and rich features. My focus landed on a business providing an Over-The-Top (OTT) platform, enabling users to effortlessly launch subscription services and creating websites sharing content like videos and other staff. For privacy reasons, let's refer to this business as `target.com`.

### Part 1: Reconnaissance

As the platform supports the users have their `yoursubdomain.target.com`&#x20;

The subdomain enumeration proved unfruitful, prompting me to concentrate on Insecure Direct Object Reference (IDOR) and Access Control vulnerabilities. I created multiple accounts with different roles, such as admin, owner, and member, passing them through Auth-Analyzer, a Burp extension I prefer for its user-friendly interface. This extension repeats requests with the provided sessions to identify access control or IDOR vulnerabilities. Throughout this process, I delved into `target.com`, understanding its features and logging interesting requests using Burp's organizer extension. This meticulous phase spanned an entire day and yielded insights such as forbidden actions for users and notable API calls like:

* Understanding the platform's functionality
* Identifying user privileges and restrictions

#### Notable API calls:

* `PUT /admin/members/{ID}` → IDOR
* `GET /admin/members` → Leaks entire org member info and IDs
* `GET /admin/sites/{ID}/products` → Access Control
* `POST /admin/members` → Try IDOR, XSS, login bugs, play with rules
* `PUT /admin/members/{ID}/update_site_creator` → Privilege escalation
* `POST /signup.json` → Duplicate registration
* `POST /admin/tokens/` → Leaks admin tokens but requires challenging parameters for brute force
* `DELETE /admin/members/{ID}` → CSRF, IDOR
* `PUT /subscriptions/{ID}`

<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption><p>My Organizer tab notes</p></figcaption></figure>

### Part 2: Classic Bugs

> F.T @karemsaqary @0d.samy @moraa

The following day, I adopted a fresh perspective to manually test for classic bugs like Cross-Site Scripting (XSS). In the team management section, I discovered an XSS vulnerability where an email address was rendered in an HTML context. Utilizing a payload like `"</p>"><img src=x onerror=confirm(88)"@gmail.com`, I successfully triggered an alert.&#x20;

It's worth mentioning that we found some stored XSSs and stored HTML Injections in the title of the website and description and collection descriptions. The WAF was blocking all tags, but a simple bypass with the TAG-in-TAG technique allowed us to trigger the alert with the payload `PAYLOAD:sallam"><<h1>img src=x onerror=confirm(88)>`.&#x20;

<div align="center" data-full-width="true">

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption><p>Stored XSSs</p></figcaption></figure>

</div>

<div align="center">

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

</div>

<div align="center">

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

</div>

Returning to the organizer tab, I explored more API calls, uncovering Blind Server-Side Request Forgery (SSRF) in the endpoint `PUT /subscriptions/{ID}` and other SSRFs with the same simplicity, as you found an API call that takes a URL as user input. Subsequently, I found other issues that didn't warrant reporting and continued experimenting with API calls.

<figure><img src="../.gitbook/assets/image (29).png" alt=""><figcaption><p>Api request vulnerable to SSRF</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>one of the SSRFs we submitted but it's duplicated</p></figcaption></figure>

### Part 3: Authorization Testing Time

Started playing with API calls, specifically the endpoint `DELETE /admin/members/{ID}` – interesting, huh? As you think, I started looking for IDOR and access control bugs and response manipulation, but unfortunately, nothing worked. So, anyway, back to our organizer tab, I started looking for another endpoint, and here it is – the API call for adding a new member to the team&#x20;

`POST /admin/members`

```json
{
  "email": "victim8800@gmail.com",
  "role": "admin",
  "site_id": {ID}
}
```

, and for changing the role of a team member, `PUT /admin/members/{ID}`

```json
{
  "siteUserId": {siteID},
  "role": "member",
  "site_id": {ID}
}
```

And, yeah, as you thought, exactly! PUT request methods are very interesting; wherever I found them, it is most likely to have an authorization issues.&#x20;

So, I wanted to test IDOR and change the ID in the path and body, but the question is how and where can I get the ID of the owner? I found out this very helpful API call that, during my investigation on the first day in this program, I always send interesting and leaky endpoints to Burp organizer with notes and checklists for the crazy ideas that I get.&#x20;

When I was thinking about how to get his ID, I switched to the Burp organizer tab and found out that there are endpoints leaking the IDs of the team members –&#x20;

`GET /admin/members?field=name&sortOrder=asc&page=1&per_page=25&query=&site_id=219531` .&#x20;

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

So, this is our hero; I simply took the IDs of the owner and put them on the request&#x20;

`PUT /admin/members/OWNER_ID`

```json
{
  "siteUserId": {siteID},
  "role": "contributer",
  "site_id": OWNER_ID
}
```

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Successful IDOR exploitation</p></figcaption></figure>

And voila, the response was 200 OK!!! Here we go! But wait!, why the hell does the GUI show that the owner is still there? Is it a false positive? But no, the owner, whenever he tries to send a request or do anything, he gets the response 403 forbidden!! And 401 not authorized, and on his side, even the GUI tells him that he is a contributor; he only can access and add content to the site :() Haha!&#x20;

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Unfortunately it is sad to say it is another duplicate</p></figcaption></figure>

And the other API call `POST /admin/members`

```json
{
  "email": "victim8800@gmail.com",
  "role": "admin",
  "site_id": {ID}
}
```

Okay, this should be for adding new members to our org, but what if… what will happen if we attempt to add a new owner? By changing the role or what if we attempted to add someone who is already a member and changing his role!!!! And fortunately, it does work! I can downgrade any other admin role to a member, but I want to affect the owner itself.&#x20;

So, I attempted to add the owner to his organization but now with permission as a contributor. Funny, huh? Now I have the highest permission in the site/org, and the owner is just a contributor that you can `DELETE /admin/members/{ID}` from the org but unfortunately attemping to delete him resulting in an error, and using match and replace simple tip false → true, I found this endpoint&#x20;

`PUT /admin/members/295019/update_site_creator` to add a new owner it worth mentioning that the UI was still saying that the owner still owner and i am still admin but the api requests and the backend showed that i can send and retreive data and do actions that the owner only has the permition to do it.

**Update**

the report in the first closed as duplicate but after reaching for mediation the report reopened but the triager out of nowhere downgraded the severity to low and now it is in the program side&#x20;

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>the triager downgradedc the severity to low</p></figcaption></figure>

### Part 4: Logic is the Best

Now I started looking for other logic flaw bugs, as noted before in the Burp organizer that the invitation link doesn't expire. This scenario involved searching for the link in Wayback, VirusTotal, and other web archives, and querying Google, Bing, and other search engines. We found some urls that are leaked via wayback but to users that are not members in organizations but i did report it anyway, as there was no email confirmation or two-factor authentication. If an attacker obtained an old invitation to any organization, they could use it with a single click to access the account.&#x20;

**Update**:\
It is out of scope so the reported marked as informative&#x20;

\


<figure><img src="../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption><p>OOS result in being info report</p></figcaption></figure>

Another scenario led me to discover that if you receive an invitation, attempting to sign up or login won't work. Instead, you must use the invitation link and set your password to create an account in the organization. I experimented with scenarios where I deleted the user from the organization before they used the invitation login link, resulting in the user being forwarded to a blank page, unable to use any core features. This prevention method also extended to users attempting to sign up with the email; they will face a message guiding them to log in with the link they received.&#x20;

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

When they use the link, now they are stuck on a blank page.

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>User Stuck on Blank page</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### End

In conclusion, let's acknowledge that participating in public bug bounty programs has its downsides, such as encountering duplicates and encountering teams that devalue bugs just to pay less (although this isn't always the case). However, there are instances where you come across feature-rich programs that are worth exploring and present a good challenge for personal growth.\
