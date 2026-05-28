# Change Phone Numbers

<details>

<summary><strong>Direct API Reuse (The GraphQL/REST Bypass)</strong></summary>

* [ ] **Re-play registration endpoints:** Locate the original onboarding/signup requests (`SetPhoneNumber`, `VerifyPhoneNumber`, `/api/v1/register/phone`) and resend them from an active, fully established session with a new number.
* [ ] **Test HTTP verb swapping:** If the registration used a `POST` request to set the number, try a `PUT` or `PATCH` request to the profile endpoint using the same parameter names.
* [ ] **Omit conditional parameters:** If the API uses a parameter like `"is_signup": true` or `"step": 3`, keep it in the request to trick the backend into thinking you are still in the onboarding phase.

</details>

<details>

<summary><strong>Parameter Pollution</strong></summary>

* [ ] **Inject secondary parameters:** Look for parameters like `mobile`, `phone`, `telephone`, or `contact_number` in general profile update requests (`POST /api/v1/user/update`), even if the UI only lets you change your name or bio.
* [ ] **Array/JSON wrapping:** If the API accepts JSON, try injecting the phone parameter into different blocks, or try parameter pollution:

```http
POST /api/user/settings

email=user@test.com&phone=+1234567890
```

</details>

<details>

<summary><strong>Test GraphQL field injection</strong></summary>



* [ ] **Test GraphQL field injection:** Query the schema or try manually adding the phone mutation fields into a standard profile update mutation (e.g., adding `phoneNumber: "+1234567890"` inside an `updateProfile` mutation).

</details>

<details>

<summary><strong>Verification &#x26; State Flaws</strong></summary>

* [ ] **Cross-account OTP verification:** Trigger the `VerifyPhoneNumber` operation from Account A, but submit the received OTP code using the session/token of Account B.
* [ ] **Force state rollback:** See if removing a connected third-party login (like Apple or Google) forces the application into a state where it asks you to re-verify or change your phone number.
* [ ] **Race conditions:** Send multiple simultaneous requests to the update or verification endpoints to see if you can bypass rate limits or state checks during execution.

***

</details>

<details>

<summary><strong>Check For OLD Mutations</strong></summary>

Always grab the introspection schema if it's enabled. Sometimes developers deprecate `SetPhoneNumber` but leave an older mutation like `AddMobileNumber` active in the background, which lacks any state restrictions entirely.

</details>

<details>

<summary><strong>Replay Attacks</strong></summary>

Bypass Disallowed Change Phone Number Feature When I created the account, I faced a function of 3 steps

1. Upload Profile Picture
2. Set Username
3. Set Phone Number and the Phone number in my profile later is not allowed to change it No "Change Button" Around it here as we can see !! So What do you think i did? Quickly, I ran into my burp requests history !! and I Inspected the full function of adding phone number !! Since the website is using "GraphQL" so the steps of adding phone number was containing 2 OperationNames
4. Adding: SetPhoneNumber
5. Verifying: VerifyPhoneNumber



By Changing the phone number in the first operation name, which is: `SetPhoneNumber` I received a 200 OK With a valid response!! & I received a verification code on the new number I added!!!

Then sent the code that I've received in the second OperationName, which was: `VerifyPhoneNumber` and It worked fine!! Totally fine!! Valid Response and the phone number changed now <3

</details>
