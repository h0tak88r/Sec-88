# Install Go tools from private repositories using GitHub PAT

Installing private Go tools from GitHub can be tricky due to authentication issues. Here’s a step-by-step guide to help you seamlessly install private Go modules.

**Prerequisites**

1. A GitHub personal access token (PAT) with `repo` scope.
2. Go installed on your machine (version 1.22.3 or higher).

**Step 1: Configure `.netrc`**

First, we need to configure the `.netrc` file to store GitHub credentials. This file allows Git to authenticate using stored credentials without prompting for username and password.

```sh
echo "machine github.com login YOUR_GITHUB_USERNAME password YOUR_GITHUB_TOKEN" > ~/.netrc
chmod 600 ~/.netrc
```

**Step 2: Set Environment Variables**

Set necessary environment variables for Git and Go.

```sh
export GIT_TERMINAL_PROMPT=1
export GITHUB_TOKEN=YOUR_GITHUB_TOKEN
```

**Step 3: Configure Go to Bypass the Proxy for Private Repositories**

Tell Go to bypass the module proxy for private repositories by setting the `GOPRIVATE` environment variable.

```sh
export GOPRIVATE=github.com/YOUR_USERNAME/*
```

**Step 4: Configure Git to Use Personal Access Token**

Instead of relying on the `.netrc` file, you can configure Git to directly use the personal access token.

```sh
git config --global url."https://YOUR_GITHUB_USERNAME:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
```

**Step 5: Disable Go Proxy Temporarily**

Sometimes, the Go module proxy can cause issues when accessing private repositories. Disable it temporarily for the installation.

```sh
export GOPROXY=direct
```

**Step 6: Install the Go Module**

Now you can install the Go module using the `go install` command.

```sh
go install github.com/YOUR_USERNAME/YOUR_REPOSITORY/cmd/YOUR_MODULE@latest
```

**Example Workflow**

Here’s the full set of commands combined into a workflow:

```sh
# Configure .netrc
echo "machine github.com login YOUR_GITHUB_USERNAME password ${GITHUB_TOKEN}" > ~/.netrc
chmod 600 ~/.netrc

# Set environment variables
export GIT_TERMINAL_PROMPT=1
export GITHUB_TOKEN=YOUR_GITHUB_TOKEN
export GOPRIVATE=github.com/YOUR_USERNAME/*
export GOPROXY=direct

# Configure git to use the token
git config --global url."https://YOUR_GITHUB_USERNAME:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"

# Attempt to install the package
go install github.com/YOUR_USERNAME/YOUR_REPOSITORY/cmd/YOUR_MODULE@latest
```

**Troubleshooting Tips**

1. **Check Token Permissions:** Ensure your GitHub token has the necessary `repo` permissions.
2. **Verify Repository Path:** Double-check the repository path and module version.
3. **Network Issues:** Ensure your network allows access to GitHub.

**Conclusion**

By following these steps, you should be able to install private Go modules from GitHub without encountering authentication issues. This approach helps automate the authentication process and ensures a smoother development workflow.

