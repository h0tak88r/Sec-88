---
description: Collaboration with Amr A'laa https://www.linkedin.com/in/amr-alaa-a14b65216/
---

# Discord OAuth Misconfig → ATO, Pre-ATO & 2FA Bypass

Some of the best bugs don't come from exotic payloads or clever encoding tricks. They come from noticing that the application _trusts something it shouldn't_. This is the story of one of those — a social-login misconfiguration on a private engagement that chained an unverified third-party account and a single disabled HTML attribute into account takeover, email-verification bypass, pre-ATO, and a two-factor authentication bypass on the account-linking flow.

I've stripped every identifying detail. The target here is just "the platform" — a consumer-facing service (think gaming/cloud account, the kind with millions of users) that let people sign in with a Discord account. Everything below is about the _technique_ and the _lessons_, not the target.

***

### The Setup: "Sign in with Discord"

The platform offered social login. You could register or log in by connecting a Discord account instead of typing an email and password. This is everywhere now — "Sign in with Google / Apple / Discord / GitHub." It's convenient, and that convenience is exactly where the trust assumptions hide.

The intended flow looks like this:

1. You click "Continue with Discord."
2. Discord confirms who you are and hands the platform some profile info — including your email.
3. The platform uses that email to either create your account or link Discord to an account you already have.

The entire security model rests on one quiet assumption: **the email handed over by the social provider is real and belongs to the person logging in.** Break that assumption and the whole thing unravels.

***

### Crack #1: An Account With No Verified Email

The first thing I tried was logging in with a Discord account that had **no verified email** — for example, an account created with just a phone number, or one where the email was never confirmed. Discord lets you create and use an account without ever verifying your email address, so getting one of these takes seconds.

Instead of rejecting it, the platform redirected me to a "create your account" page asking me to accept the terms. But the interesting part was the **email field**: it was empty and rendered as _disabled_. The application was essentially saying:

> I didn't get a verified email from the provider, so I'll just show you a greyed-out box and let you continue.

That greyed-out box was the whole ballgame.

***

### Crack #2: `disabled` Is Not a Security Control

Here's the lesson every web hacker learns early and every developer forgets occasionally: **a `disabled` attribute on an input is a UI suggestion, not a server-side rule.** It stops a normal user from typing in the box. It does absolutely nothing to stop someone who opens devtools.

So I opened the browser's element inspector, found the email input, and removed the `disabled` attribute. Now the "uneditable" field was editable.

Then I typed in an email address that **wasn't mine** — an address belonging to someone else entirely — and continued. The platform accepted it and created the account, never once checking that I actually controlled that inbox.

That single step already gave me two problems for the platform:

* **Email verification bypass** — I registered an account tied to an email I never proved I owned.
* **Pre-account-takeover (pre-ATO)** — if a real user hadn't signed up yet, I could "pre-register" their email. When they later tried to join, the account would already exist under my control. They'd be walking into a trap set before they ever arrived.

***

### Crack #3: Linking Onto an Existing Victim — and a 2FA Bypass

The bigger question: what if the email I entered already belonged to an existing account on the platform?

When the email matched an existing user, the platform tried to **link my attacker-controlled Discord account onto the victim's account**. What happened next depended on whether that victim had 2FA — and it's worth being precise about the two cases, because they have very different impact:

**Case A — victim has no 2FA → straight account takeover.** The linking went through and the attacker's Discord was now attached to the victim's account. From there the attacker just clicks "Continue with Discord" and lands inside the victim's account. Clean ATO.

**Case B — victim has 2FA enabled → 2FA bypass on the linking step.** Here's the interesting part. The platform let the attacker's Discord get **linked to the victim's account without entering 2FA code** — the linking action itself skipped the second factor. _But_ — and this is the important nuance — that link alone did **not** hand the attacker full access to the victim's internal account. 2FA still stood between the attacker and actually getting inside.

So Case B is a **2FA bypass for account linking, not a full takeover.** The attacker defeated the second factor for the _act of linking_ an OAuth provider, but didn't thereby walk into the dashboard. That's a meaningful weakness — you've broken a control that's supposed to be unbreakable — but it stops short of "I'm now in your account."

That distinction matters, and it's exactly what drove the final severity (more on that below). A lot of writeups blur "I bypassed 2FA on one step" into "I took over the account." They're not the same thing, and being honest about which one you have is what keeps your reports credible.

***

### The Full Chain

Put the cracks together and you get the full picture:

1. Log in with a Discord account that has no verified email → reach the account page with the disabled email field.
2. Remove `disabled` in devtools and enter the **victim's** email.
3. **No account exists for that email yet** → **pre-ATO**: the email is now reserved under attacker control, trapping the real user before they ever sign up.
4. **Account exists, no 2FA** → linking the attacker's Discord = **full account takeover**: attacker logs in via Discord and is inside.
5. **Account exists, 2FA enabled** → the attacker's Discord still gets **linked without the 2FA code** = **2FA bypass for linking** — a broken control, though not full internal access on its own.

Each branch is a distinct outcome with a distinct severity. Being clear about which is which is the difference between an accurate report and an overclaim.

***

### A Detour Worth Remembering: "Is This Even Our Bug?"

There's one more part of this story that's pure bug-hunting craft. When a finding lives in a third-party component — an open-source identity stack, an auth library, a managed SSO provider — there's a natural reflex to say "that's the vendor's bug, not ours."

This finding ran straight into that. The platform initially pointed upstream:

> This is the identity component's behavior — go report it there.

I did. The upstream maintainers looked at it and pushed back the other way:

> The component can absolutely enforce verified email and re-authentication before linking — this is a misconfiguration in how the platform integrated us, not a flaw in our product.

That's the classic hot-potato, and a less persistent hunter loses the report right there, with each party pointing at the other and nobody paying.

What resolved it was **evidence, not argument.** I showed that _other_ deployments of the same underlying technology handled the social-login flow correctly and securely. If the component were inherently broken, everyone using it would be vulnerable — but they weren't. That demonstrated the root cause was the platform's own configuration, not the upstream product, and the report was validated.

The lesson: **"it's a misconfiguration of an upstream component" is not the same as "it's not exploitable on the live target."** A vulnerability that's real and reachable in production is part of the deployed system's security posture, regardless of which layer technically introduced it. If you can prove the same stack is safe when configured properly elsewhere, you've located the responsibility precisely — and that proof is what gets a disputed report over the line.

***

### Takeaways for Hunters

* **Social login is a goldmine of trust-assumption bugs.** Always ask: _does the app verify the email the provider claims, or does it just believe it?_ Then try an account with an unverified/absent email.
* **`disabled` and friends are an invitation.** Any field the UI tries to lock is worth unlocking in devtools and seeing what the server does with it.
* **Chase the 2FA-skip paths.** Account-linking, OAuth connect, password-reset, "add a recovery method" — these are the flows where second factors get forgotten. A 2FA bypass elevates an otherwise ordinary bug dramatically.
* **Think in chains — and split the outcomes.** One disabled field branched into pre-ATO, a no-2FA takeover, and a 2FA-linking bypass. Map each branch to its precondition and its real impact rather than collapsing them into one headline.
* **Don't abandon a report at the first 'not our bug.'** If it's exploitable in production, it counts. Prove where the root cause lives with comparative evidence, and be persistent but professional.

The flashiest part of this report was a `disabled` attribute deleted in one click. The valuable part was understanding _why_ the application trusted that field, following the trust all the way down — and being precise about exactly how far each outcome reached. That's the whole game.

Stay in scope, hunt ethically, and keep pulling on the loose threads.
