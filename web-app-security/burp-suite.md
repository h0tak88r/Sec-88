# Burp Suite

#### Burp version to 1.7.36 or higher.

[Professional / Community 1.7.36 | Releases (portswigger.net)](https://portswigger.net/burp/releases/professional-community-1-7-36)

*   Attacks Types

    |               |                                                                                                                                    |
    | ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
    | Attack Type   | Description                                                                                                                        |
    | Sniper        | Uses a single payload list; Replaces one position at a time                                                                        |
    | Battering Ram | Uses a single payload list; Replaces all positions at the same time                                                                |
    | Pitchfork     | Each position has a corresponding payload list; So if there are two positions to be modified they each get their own payload list. |
    | Cluster Bomb  | Uses each payload list and tries different combinations for each position                                                          |
* Free Extensions to use
  * `Software Vulnerability` → \[ CVE’s ]
  * `Retire.js` → \[ JQuery Flaws]
  * `JSON Web Tokensor JWT editor` → \[JWT pentest]
  * `param miner` → \[Web Cache Poisoning]
  * `Decoder Improved` → [https://portswigger.net/bappstore/0a05afd37da44adca514acef1cdde3b9](https://portswigger.net/bappstore/0a05afd37da44adca514acef1cdde3b9)
  * `Autorize` - \[AC Bugs]\
    ● `Backslash Powered Scanner` - Advanced payloads while active scanner\
    ● `Google Authenticator` - Automation in 2FA\
    ● `Java Serial Killer` - payload generation tool for Java object deserialization\
    ● `Handy Collaborator` - OOB requests while manual test using Repeater\
    ● `HUNT Suite` - Identify common parameters for known vulnerabilities\
    ● `J2EEScan` - Scanner for Java based application\
    ● `Logger++` - Keeps logs of everything\
    ● `SAML Editor/SAML Encoder-Decoder/SAML Raider` - SAML requests\
    ● \`WSDLER/WSDL Wizard \`\`- Web service automatio
*   Burp Collaborator

    ● A network service which helps to discover Blind vulnerabilities such as SQL Injection, XML Injection, Cross-Site Scripting etc.\
    ● Uses a specially crafted dedicated domain name and reports as an issue such as External Service Interaction, SQL Injection etc.
* Scope
  *   **Set scope** to advanced control & use **string of target name** (not a normal FQDN)

      * Goal: Show only links that have _tesla_ in the URL in the _Site map_  Click _yes_ for to \_"…stop sending out of scope items to the history…"\_Show only in scope items in the _Target_ / _Site map_

      [![](https://pentester.land/blog/levelup-2018-the-bug-hunters-methodology-v3/burp-spider-3\_hucacd5fddf15e0fb730f80fb9c969f0e4\_40794\_636x0\_resize\_q75\_h2\_box\_3.webp)](https://pentester.land/blog/levelup-2018-the-bug-hunters-methodology-v3/burp-spider-3\_hucacd5fddf15e0fb730f80fb9c969f0e4\_40794\_636x0\_resize\_q75\_h2\_box\_3.webp)

      [![](https://pentester.land/blog/levelup-2018-the-bug-hunters-methodology-v3/burp-spider-4\_huc09f413a13bd271c7d81386cebf63cc3\_4981\_670x0\_resize\_q75\_h2\_box\_3.webp)](https://pentester.land/blog/levelup-2018-the-bug-hunters-methodology-v3/burp-spider-4\_huc09f413a13bd271c7d81386cebf63cc3\_4981\_670x0\_resize\_q75\_h2\_box\_3.webp)
