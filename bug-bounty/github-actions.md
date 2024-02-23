---
description: Automating Bug Bounty with GitHub Actions
---

# GitHub Actions

### Understanding GitHub Actions

GitHub Actions is a versatile platform for continuous integration and continuous delivery (CI/CD), automating various aspects of software development. It facilitates the creation of workflows to automate tasks like building, testing, and deploying code triggered by events such as code pushes and pull requests.

GitHub Actions provides virtual machines (VMs) with Linux, Windows, and macOS operating systems or allows the use of self-hosted runners for more control. It acts as a virtual environment, executing tasks configured through a workflow file in YML format.

### Story

In my GitHub projects, discovering GitHub Actions sparked the idea of leveraging it for bug bounty automation. Excited about the prospect of streamlining processes, I delved into GitHub's documentation to explore its potential further.

### How to Implement GitHub Actions

1. Navigate to your GitHub repository.
2. Access the "Actions" section.
3. Set up a workflow by defining a YML file.
4. Reap the benefits of automated tasks in your development process.

### Explaining the Workflow File

A sample GitHub Actions workflow file might look like this:

```yaml
name: bug-bounty-automation
on: [push]

jobs:
  reconnaissance:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repo
        uses: actions/checkout@master
      
      - name: Setup Tools
        run: |
          go version
          go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest    
          
      - name: Run Subfinder
        run: subfinder -silent -dL scope.txt -o subfinder.txt
```

* `name: bug-bounty-automation` specifies the workflow name.
* `on: [push]` triggers the workflow on code push.
* `jobs:` groups tasks to execute.
* `runs-on: ubuntu-latest` configures the job on the latest Ubuntu.
* `uses: actions/checkout@master` copies repo files.
* `uses: actions/setup-go@v2` installs Go, needed for `subfinder`.
* `run` commands execute various workflow steps.

[Workflow-Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions\_)

### Limitations of GitHub Actions

* **Job execution time**: Limited to 6 hours.
* **Workflow run time**: Limited to 35 days.
* **API requests**: 1,000 requests per hour.
* **Concurrent jobs**: Depend on GitHub plan.
* **Job matrix**: Generates max 256 jobs per run.
* **Workflow run queue**: Max 500 runs in a 10-second interval.

[GitHub-Actions-Limits](https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration)

### Tips and Workarounds

* Avoid resource-intensive tasks.
* Use small bash scripts for multiple commands.
* Employ webhooks for notifications, e.g., sending results via Telegram Bots.

For Telegram notifications:

1. Create a Telegram bot via @BotFather.
2. Note the HTTP API Token.
3. Use token and chat ID to send results.

```bash
cat results.txt | curl -X POST -F "document=@-" "https://api.telegram.org/bot<YOUR-BOT-TOKEN>/sendDocument" -F "chat_id=<YOUR-CHAT-ID>"
```

### Benefits of GitHub Actions

* Easy setup and configuration.
* Minimal logging needed.
* No additional cost.
* Accessible data for reference.
* Versatile automation possibilities.

### Conclusion

GitHub Actions, within its limits, is a powerful tool for automating tasks like bug bounty reconnaissance. Setting up private workflows for reconnaissance tasks, I've streamlined repetitive tasks and received results via a Telegram bot. The tool's potential applications are vast, offering hands-free automation to enhance development and automation workflows. Feel free to explore and experiment to discover innovative uses!
