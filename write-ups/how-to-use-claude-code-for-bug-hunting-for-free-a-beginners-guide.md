# How to Use Claude Code for Bug Hunting — For Free (A Beginner's Guide)

If you're brand new to AI-assisted bug bounty and every guide you've opened assumes you already know what "MCP" or "skills" or "agentic" means — this post is for you. We'll start from absolute zero, explain every word in plain language, and then walk through exactly how to wire up Claude Code as a free bug-hunting partner.

No prior AI knowledge required. If you can open a terminal and copy-paste, you can follow along.

> **One rule before anything else:** only ever test targets you are _allowed_ to test — a bug bounty program that lists the asset in scope, your own lab, or a deliberately-vulnerable practice site. Pointing these tools at random websites is illegal, full stop. Every tool below assumes you stay in scope.

***

### Part 1: The Words Everyone Throws Around (Explained Simply)

Before we install anything, let's kill the jargon. These four terms come up constantly.

#### What is "AI" here, really?

When we say "AI" in this guide, we mean a **Large Language Model (LLM)** — think of it as an extremely well-read assistant that has read most of the public internet and can write text, code, and explanations on demand.

Picture a very smart intern who has memorized thousands of security write-ups, knows how to write code, never gets tired, and works for free (or cheap). That intern can read a web page, notice something suspicious, suggest the next test, and even write up the report. That's the "AI" we're putting to work.

**Claude** is one of these assistants (made by a company called Anthropic). **Claude Code** is a version of Claude that lives in your terminal (the black command-line window) and can actually _do_ things — run commands, read files, call tools — instead of just chatting.

#### What is an MCP?

Here's the limitation: by itself, the AI intern can only _talk_. It can't click around the internet, it can't query a search engine, it can't poke a website. It just thinks and writes.

An **MCP (Model Context Protocol)** is the "USB port" that lets the AI plug into real tools.

Think of the AI as a smart brain in a jar. On its own it can reason, but it has no hands. An MCP is like giving it a robotic arm. One MCP gives it the ability to search the web. Another gives it the ability to query Shodan (a search engine for internet-connected devices). Another lets it talk to your proxy tool to inspect web traffic.

So: **MCP = a connector that gives the AI a new superpower / a new hand to use a real-world tool.** You install an MCP once, and from then on the AI can use that tool whenever it needs to.

#### What are "Skills"?

If MCPs give the AI _hands_, **Skills** give it _expertise_.

A Skill is just a structured instruction file (usually called `SKILL.md`) that teaches the AI a specific methodology — "here's exactly how a professional hunts for SQL injection," "here's the checklist a pro runs before submitting a report," "here are the 26 real-world patterns of IDOR bugs that actually got paid."

Here's the clever part: skills load **only when relevant**. You don't have to remember which one to turn on. If you tell Claude "this endpoint takes a `?url=` parameter," the SSRF skill quietly loads itself because it recognizes the topic. You describe what you see in plain English, and the right expert knowledge shows up.

Think of it like a folder of cheat-sheets that the intern automatically pulls out the moment the conversation touches that subject.

#### Quick analogy to tie it together

* **AI/LLM** = a brilliant, well-read intern with no hands.
* **Claude Code** = that intern, sitting in your terminal, now allowed to run commands.
* **MCP** = robotic hands that let the intern use real tools (web search, Shodan, your proxy).
* **Skills** = cheat-sheets that turn the generalist intern into a specialist on demand.

That's the whole mental model. Everything below is just _getting these four things set up without paying for them._

***

### Part 2: The First Step — Getting a Model to Run for Free

Claude Code normally runs on Anthropic's paid models. To use it for free, we feed it a _different_ model through a side door. There are several approaches, and the smart move is to set up **more than one** so that when one hits a rate limit (a temporary "you've used too much, slow down" wall), you instantly switch to another.

Let's go through the approaches from easiest to most flexible.

#### Approach 1: Free Claude/model gateways (the "Chinese dashboards")

There are a number of websites that hand out free access to strong models (sometimes even Claude-compatible ones). A couple of examples:

* `https://freemodel.dev/dashboard`
* `https://tokenlb.net/dashboard/models`

These sites give you an **API key** (a long secret password-like string that proves you're allowed to use the model) and a **base URL** (the address Claude Code should send its requests to instead of Anthropic's official one).

**The insider tip — how to find these before everyone else:**

These services pop up, fill up, and get replaced constantly. The people who run and announce them are often very active on Twitter/X, frequently posting in Chinese. So the trick is to **follow the right accounts and search the right keywords**.

Try searching Twitter/X for terms like:

* `免费 claude code` (free claude code)
* `claude 镜像` (claude mirror/proxy)
* `claude code 免费 key`
* `免费 API 中转` (free API relay)
* in English: `free claude code api`, `claude code mirror`, `free anthropic proxy`

When you find an account that shares a working one, follow them — they usually post the next one when the current dashboard fills up. Set up a Twitter list of these accounts so your feed becomes an early-warning system for fresh free keys.

> **Safety note:** treat these third-party gateways as untrusted. Don't paste real credentials, personal data, or anything sensitive through them, and never use them for anything beyond practice and learning. You're sending your traffic through someone else's server.

#### Approach 2: The `free-claude-code` project

There's a popular open-source project that acts as a **translator/proxy** sitting between Claude Code and _any_ model provider you want:

`https://github.com/Alishahryar1/free-claude-code`

In plain terms: Claude Code thinks it's talking to Anthropic, but this little program quietly reroutes the conversation to a free provider of your choice — NVIDIA's free tier, Google's Gemini free tier, DeepSeek, OpenRouter's free models, and many more. It even includes a local admin web page where you paste a free API key, click "validate," and you're done.

The flow is roughly: install it, start its server (`fcc-server`), open the admin page, drop in a free provider key (NVIDIA NIM is a common free starting point), then launch Claude Code through its wrapper command (`fcc-claude`) instead of the normal `claude`. From that point Claude Code runs on the free model.

This is a great option because it puts _many_ free providers behind one consistent setup, and if one provider's free quota runs dry you just switch the model in the admin page.

#### Approach 3: OpenCode free models + `ocgo`

**OpenCode** is another gateway that exposes a catalog of models, including genuinely free ones like **DeepSeek**, **MiniMax**, and **MiMo**. These are strong, capable models that cost nothing on their free tiers — perfect for grinding through recon and analysis without burning money.

To make Claude Code use them comfortably, there's a neat little launcher called **`ocgo`**:

`https://github.com/emanuelcasco/ocgo`

`ocgo` is a small wrapper that launches Claude Code (or other agents) already wired up to an OpenCode model. So instead of manually exporting a bunch of environment variables every time, you run one short command and it boots Claude Code straight onto, say, DeepSeek. It genuinely smooths out the experience.

#### Approach 4 (bonus): Same trick, different agent — Strix for pentesting

Everything above is about _models_, not specifically about Claude. That means the exact same free models can power **other** security agents too.

One worth knowing is **Strix**:

`https://github.com/usestrix/strix`

Strix is an autonomous pentesting agent — point it at a target (that you're authorized to test) and it runs an automated assessment. Because it also lets you choose which model backs it, you can feed it the _same_ free OpenCode model (e.g. DeepSeek via OpenCode) and run deep scans without paying for a premium model. We'll include a ready-made shortcut for this below.

#### The Pro Move: Aliases for Instant Switching

Here's the thing that ties it all together. Free tiers hit **rate limits** — you'll be cruising along and suddenly get blocked for a while. The professional habit is to have _several_ setups ready and a one-word command to jump between them.

You do this with **aliases**. An alias is just a nickname for a longer command. You define it once in your shell's config file — `~/.zshrc` if you use zsh (default on modern macOS) or `~/.bashrc` if you use bash (common on Linux) — and from then on, typing the short nickname runs the whole long command.

Open that file (`nano ~/.zshrc` or `nano ~/.bashrc`), paste your aliases at the bottom, save, then run `source ~/.zshrc` (or `source ~/.bashrc`) to load them. Now you have a panel of switches.

Here's a real example set. Replace every `<apiKeyHere>` with your actual key for that service, and adjust paths/usernames to match your machine:

```bash
# Make sure locally-installed Python tools are on your PATH
export PATH="$PATH:/Users/sallam/Library/Python/3.9/bin"

# (Optional) point Claude Code at a local proxy if you run one
# export ANTHROPIC_BASE_URL=http://127.0.0.1:3456
# export ANTHROPIC_AUTH_TOKEN=unused

# Switch 1 — run Claude Code with a direct Anthropic-compatible API key
alias claudecc='unset ANTHROPIC_AUTH_TOKEN && export ANTHROPIC_API_KEY=<apiKeyHere> && claude'

# Switch 2 — launch Claude Code on a free OpenCode model (DeepSeek) via ocgo,
# with permission prompts skipped for a smoother autonomous run
alias claudego='ocgo launch claude --model deepseek-v4-pro -- --dangerously-skip-permissions'

# Switch 3 — run the Strix pentesting agent on the SAME free DeepSeek model
alias strix-hunter='STRIX_LLM=opencode/deepseek-v4-pro \
  OPENCODE_API_KEY=sk-<apiKeyHere> \
  OPENCODE_BASE_URL=https://opencode.ai/zen/go/v1 \
  strix --scan-mode deep --target'

# Switch 4 — route Claude Code through a free gateway (agentrouter style)
alias claudear='ANTHROPIC_BASE_URL=https://agentrouter.org/ ANTHROPIC_AUTH_TOKEN=sk-<apiKeyHere> claude'

# Switch 5 — launch Claude Code through the free-claude-code wrapper
alias claudefree='fcc-claude --dangerously-skip-permissions'

# (Optional) defaults for Strix if you'd rather export once than inline above
# export STRIX_LLM=opencode/deepseek-v4-pro
# export OPENCODE_API_KEY=sk-<apiKeyHere>
```

Now your daily workflow looks like this: start with `claudego`. Hit a limit? Switch to `claudefree`. That one's slow today? `claudear`. Want to run an autonomous pentest on the same free model? `strix-hunter target.com`. You're never stuck waiting on a single provider.

> **A note on `--dangerously-skip-permissions`:** this flag tells Claude Code to stop asking "are you sure?" before each action. It makes autonomous runs smoother, but as the name screams, it removes a safety check. Only use it on targets you fully control or are authorized to test, and ideally inside a dedicated VM or container, never on a machine with sensitive data.

***

### Part 3: The Second Step — MCPs (Giving Your AI Its Hands)

Now that Claude Code is running on a free model, let's plug in some tools. Remember: an MCP is a connector that gives the AI a real-world capability. You typically register them once, and Claude Code shows them as "connected" on startup.

There are _tons_ of MCPs out there, but here's a focused, practical set that actually earns its place in a bug-hunting workflow.

#### vibe-hacking (for Caido)

`https://github.com/vvvvvvvvvvel/VibeHacking`

**Caido** is a modern web proxy — the tool that sits between your browser and the target so you can see and tamper with every request (think of it as a lighter, sleeker alternative to Burp Suite). The **vibe-hacking** MCP connects Claude directly to Caido, so the AI can read your captured traffic, understand the requests, and reason about what to test next — without you copy-pasting requests back and forth.

#### Shodan MCP

**Shodan** is a search engine for internet-connected devices — servers, cameras, databases, exposed panels. A Shodan MCP lets Claude query it directly during recon to discover a target's exposed infrastructure. In the example setup it's a small local Python script:

```
shodan: python3 /Users/sallam/.local/mcp/shodan-mini.py
```

#### fetch + tavily (web reach)

These two give the AI eyes on the open web:

```
fetch:  npx -y @mokei/mcp-fetch        # lets Claude pull and read any web page
tavily: npx -y tavily-mcp              # lets Claude run real web searches
```

`fetch` is how the AI reads a specific page (docs, a JS file, a write-up). `tavily` is how it _searches_ — for example, looking up known CVEs for a technology it just fingerprinted on your target.

#### h1-brain (HackerOne knowledge)

```
h1-brain: /Users/sallam/h1-brain/venv/bin/python /Users/sallam/h1-brain/server.py
```

A local MCP that gives Claude a memory/knowledge layer around HackerOne data — useful for pulling context about programs, past disclosed reports, and patterns relevant to what you're hunting.

#### sec-88 (your own knowledge base over HTTP)

```
sec-88: https://sallam.gitbook.io/sec-88/~gitbook/mcp   (HTTP)
```

This one's a nice trick: it exposes a GitBook knowledge base _as_ an MCP over HTTP. So your personal notes, methodology, and references become something the AI can query live while it works.

#### vibe-hacking over HTTP

```
vibe-hacking: http://192.168.100.78:3333/mcp   (HTTP)
```

The same vibe-hacking tool can also run as an HTTP service on your local network — handy if you're running the proxy on one machine and Claude on another.

#### The general-purpose trio

These three aren't security-specific, but they massively level up _any_ agent:

```
puppeteer:           npx -y @modelcontextprotocol/server-puppeteer
sequential-thinking: npx -y @modelcontextprotocol/server-sequential-thinking
memory:              npx -y @modelcontextprotocol/server-memory
```

* **puppeteer** gives Claude a real, controllable browser — it can load pages, click, fill forms, and observe JavaScript-rendered content (essential for modern web apps).
* **sequential-thinking** lets Claude break a hard problem into ordered steps and reason through them methodically instead of rushing to an answer — great for multi-stage exploit chains.
* **memory** gives Claude a persistent memory so findings and context survive across the session.

Together this set means your AI can search the web, read pages, drive a browser, query Shodan, inspect your proxy traffic, lean on HackerOne context and your own notes, and think step-by-step. That's a serious recon-and-analysis rig — all bolted on through MCPs.

***

### Part 4: The Third Step — Skills (Turning the Generalist into a Specialist)

MCPs gave the AI hands. Skills give it the _brain of a senior bug hunter_. Remember: skills are methodology files that auto-load by topic. Let's go through the ones worth installing.

#### The cybersecurity skills you _can_ add (but won't lean on much)

`https://github.com/mukul975/Anthropic-Cybersecurity-Skills`

Install with:

```
npx skills add mukul975/Anthropic-Cybersecurity-Skills
```

This is a solid general cybersecurity skill collection. It's worth having installed, but in day-to-day bug hunting you'll reach for the bug-bounty-specific bundles below far more often. Keep it around as broad backup knowledge; don't make it your main driver.

#### The main workhorse: `claude-bug-bounty`

`https://github.com/shuvonsec/claude-bug-bounty`

This is the bundle you'll actually live in. It turns Claude Code into a full bug-bounty pipeline — recon, testing, validation, and report-writing — all driven by simple slash commands. Install it (it sets up both the scanning tools and the skills/commands into `~/.claude/`), then you get a clean workflow:

```
/recon target.com     # map the attack surface: subdomains, live hosts, URLs, a nuclei sweep
/hunt target.com      # actually test for bugs: IDOR, auth bypass, SSRF, XSS, SQLi, logic flaws...
/validate             # run the "7-Question Gate" to kill weak findings before you waste time
/report               # generate a submission-ready HackerOne/Bugcrowd/Intigriti/Immunefi report
```

The two commands you mentioned loving — and for good reason:

* **`/autopilot target.com`** — the fully autonomous loop. It runs the entire chain by itself: scope → recon → hunt → validate → report, with safety checkpoints along the way. You point it at an in-scope target and let it work.
* **`/hunt target.com`** — the targeted testing engine. It probes a long list of vulnerability classes (the bundle covers around 20 web bug types, from IDOR and SSRF up to request smuggling and SSO attacks) and tells you what's worth chasing.

The standout feature is the **7-Question Gate** behind `/validate`. New hunters waste enormous time writing reports for findings that get rejected as "N/A" (not applicable / not a real bug). The gate forces every candidate finding through seven brutal questions — _Can an attacker do this right now? Is it in scope? Is the impact real, not just "technically possible"?_ — and kills the weak ones before you waste an hour writing them up. This single habit is what separates productive hunters from noise.

It also has **memory** — patterns it finds on one target inform the next, and sessions pick up where they left off.

#### The depth upgrade: `Claude-BugHunter`

`https://github.com/elementalsouls/Claude-BugHunter`

If `claude-bug-bounty` is the workflow, this is the **encyclopedia**. It's a much larger skill bundle — dozens of skills — where each vulnerability class is backed by patterns curated from _hundreds of real, disclosed HackerOne reports_. So when Claude tests for XSS, it's drawing on 170+ real-world XSS reports that actually got paid; for IDOR, 26 disclosed reports; for RCE, 67. It's not guessing from abstract theory — it knows the chain templates that real triagers rewarded.

The killer feature for a beginner is the **"what you're seeing → which skill loads" lookup**. You don't need to know the name of the attack. You just notice a pattern on the target and the right specialist activates:

* See a numeric ID in the URL like `/users/42`? → the IDOR skill loads.
* See a parameter like `?url=` or `?redirect=`? → the SSRF skill loads.
* Land on a `/graphql` endpoint? → the GraphQL skill loads.
* Spot a JWT token in a cookie? → the API-misconfig/JWT skill loads.

It shares the same slash commands (`/recon`, `/hunt`, `/triage`, `/report`, `/validate`, `/chain`, `/autopilot`) so it slots right into the workflow you already learned. It also adds enterprise-grade coverage (cloud IAM, identity providers, perimeter appliances) for when you graduate to bigger targets, plus strong reporting hygiene like auto-redacting cookies and personal data from your screenshots.

#### The red-team library: `claude-red`

`https://github.com/SnailSploit/claude-red`

This one widens the lens from "bug bounty" to **offensive security in general**. It's a big curated library of attack skills organized into categories — web (SQLi, XSS, SSRF, deserialization, request smuggling, WAF bypass, business logic...), auth (JWT, OAuth), cloud, mobile, wireless, exploit development, fuzzing, recon, and AI security.

Install it straight into Claude's skill folder:

```
git clone https://github.com/SnailSploit/claude-red ~/.claude/skills/claude-red
```

Or grab just the categories you want (web + AD, for example) using a sparse checkout. Like the others, skills load on demand from conversational triggers — mention SQLi and the `offensive-sqli` skill primes itself.

You won't use every category for web bug bounty, but its web and recon skills are excellent, and having exploit-dev and fuzzing knowledge on tap is handy as you grow.

***

### Putting It All Together — Your Free Stack

Here's the whole picture, start to finish:

1. **Model (free):** Set up two or three free model sources (a gateway from Twitter, `free-claude-code` with NVIDIA/Gemini/DeepSeek, and OpenCode via `ocgo`). Wire them to **aliases** so you can switch with one word when you hit a rate limit. Bonus: the same free models power **Strix** for autonomous pentests.
2. **MCPs (hands):** Plug in web reach (`fetch`, `tavily`), a real browser (`puppeteer`), recon power (`shodan`), proxy integration (`vibe-hacking` for Caido), knowledge layers (`h1-brain`, `sec-88`), and reasoning/memory (`sequential-thinking`, `memory`).
3. **Skills (brain):** Install `claude-bug-bounty` as your main driver (live in `/hunt` and `/autopilot`), add `Claude-BugHunter` for disclosed-report depth, layer in `claude-red` for broader offensive coverage, and keep the general `Anthropic-Cybersecurity-Skills` as backup.

Then the daily loop is simple: launch Claude Code on a free model, point it at an **in-scope** target, run `/recon`, then `/hunt` (or `/autopilot`), let `/validate` kill the weak findings, and `/report` the real ones.

***

### A Final, Serious Word on Ethics and Legality

Running these tools against a website you don't have permission to test is a crime in most countries — it doesn't matter that "the AI did it." You're responsible for every request your stack sends. Read each program's scope and rules before you point anything at it, stay inside that scope, and never weaponize findings.

Used responsibly, this setup gives a complete beginner — for _free_ — the kind of tireless, knowledgeable hunting partner that simply didn't exist a couple of years ago. Set it up, practice on legal targets, and learn the craft underneath the automation. The AI is the force multiplier; _you_ are still the hunter.

Happy (ethical) hunting.
