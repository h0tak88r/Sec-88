---
cover: https://miro.medium.com/v2/resize:fit:680/1*q-hYfrbvZ1_x1mRIR7FUiw.jpeg
coverY: 0
---

# Inside the Classroom: How We Hacked Our Way Past Authorization on a Leading EdTech Platform

Hello, fellow hackers! After some deep diving into a private bug bounty program on HackerOne, I uncovered an interesting vulnerability on a well-known learning platform. What started as a curiosity about how students and teachers interact on this platform quickly turned into a fascinating journey of brute force, code hunting, and a bit of creativity. Let me walk you through the process.

### The Entry Barrier: Authorization Codes

When you first land on the platform's homepage, you're immediately met with a barrier: there's no way in without an authorization code. These codes are distributed by teachers or administrators, and without one, you're stuck on the outside looking in. The code itself is a six-digit number—simple yet hard enough to guess by random chance.

<figure><img src="../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

Naturally, this piqued my interest. I started investigating the structure of these codes and realized they were being sent in GET requests. That's where the fun began.

<figure><img src="../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

### The Brute Force Approach

Using tools like ffuf and Burp Suite, I scripted a brute force attack on these codes. Considering the popularity of the platform and the number of active users, I figured there had to be plenty of active codes. And I was right—after some effort, I managed to uncover several valid codes. With one of these codes in hand, I bypassed the entry authorization code and successfully registered on the platform.

<figure><img src="../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

Once inside, I was granted access to the student profile and dashboard. But that wasn’t the end of the road.

### The Core: Accessing Classes

The real treasure on this platform is the classes themselves. However, just like the initial entry, access to a class requires a class code—another barrier set up by the teachers. My first instinct was to try the brute force approach again, but this time I hit a wall. The platform had implemented rate limiting on class code attempts, effectively blocking my attempts to guess the codes.

<figure><img src="../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

### A New Approach: Hunting for Leaks

At this point, I had to get creative. If brute force wasn't going to work, I needed another way to get my hands on those elusive class codes. That's when it hit me: what if these codes were inadvertently leaked somewhere else? Perhaps in URLs shared by teachers or in publicly accessible materials like PDFs.

I started digging into archived URLs and documents but initially found nothing. Then, a realization struck—I had been looking in the wrong place. The class code validation wasn’t handled by the main domain I had been focusing on. Instead, the requests were being routed through a different domain entirely.

### The Breakthrough

With this new domain in mind, I intercepted the requests using Burp Suite, extracted the relevant information, and unleashed my custom tool on it. This tool crawled through all the URL archives and performed regex matching to sniff out anything suspicious. And bingo! I hit the jackpot.

Suddenly, I had a list of class codes that had been unintentionally exposed. Armed with these codes, I joined a class and found myself with access to even more features, including details about other students and class-specific resources.

<figure><img src="../.gitbook/assets/image (111).png" alt=""><figcaption><p>the results of the tool </p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (112).png" alt=""><figcaption><p>Whe valid code signin code returns in the response</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (113).png" alt=""><figcaption><p>we are in</p></figcaption></figure>

### Conclusion: Lessons Learned

This exploration into the learning platform was a reminder that sometimes, the direct route isn't always the best one. By thinking outside the box and combining brute force with creative investigation, I was able to uncover significant vulnerabilities that could compromise the platform's security.

I hope this story serves as both a guide and inspiration. Always stay curious, keep digging, and remember—sometimes the answers are hiding where you least expect them.

Happy hacking!

