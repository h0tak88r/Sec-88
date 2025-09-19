# How to Grep/Install IPA

#### 1) Install `ipatool` (macOS, easiest)

```bash
# if you have Homebrew
brew install ipatool
```

(you can also download a release binary from the repo releases page). ([GitHub](https://github.com/majd/ipatool))

***

#### 2) Authenticate with your Apple ID (interactive = recommended)

```bash
# interactive (recommended — won't leave your password in shell history)
ipatool auth login -e you@example.com
```

`ipatool` will prompt for your Apple ID password and — if your account has 2FA — will ask for the 6-digit code sent to a trusted device. You _can_ provide `-p` and `--auth-code` for non-interactive use, but avoid passing your raw password on the command line on a shared machine. ([GitHub](https://github.com/majd/ipatool))

To check your logged-in account:

```bash
ipatool auth info
```

(prints the App Store account info). ([GitHub](https://github.com/majd/ipatool))

***

#### 3) Confirm the app identity (optional)

If you want to confirm the ID → bundle mapping before downloading, `ipatool` can search or list versions. The app id `1624045881` corresponds to **Flink Workforce** (bundle `com.goflink.workforce`). ([platform.foxdata.com](https://platform.foxdata.com/cn/app-profile/1624045881/US/as?utm_source=chatgpt.com))

***

#### 4) List available versions for App ID `1624045881`

```bash
ipatool list-versions -i 1624045881 --format json
```

This shows available versions and their **external version ids** and the app's bundle identifier. Use `--format json` to make output easy to parse (pipe to `jq` if you like). ([GitHub](https://github.com/majd/ipatool))

Example (parse with `jq`):

```bash
ipatool list-versions -i 1624045881 --format json | jq '.'
```

***

#### 5) Download the IPA (latest by default)

```bash
# download latest
ipatool download -i 1624045881 -o ./FlinkWorkforce.ipa
ipatool download -i 1624045881 -o ./FlinkWorkforce.ipa --purchase
```

If you want a specific version, pass the external version id you found:

```bash
ipatool download -i 1624045881 --external-version-id <EXTERNAL_ID> -o ./FlinkWorkforce.ipa
```

If the account does not already "own" the app you can try the `--purchase` flag to obtain a license during download:

```bash
ipatool download -i 1624045881 -o ./FlinkWorkforce.ipa --purchase
```

(see `ipatool download --help` for flags). ([GitHub](https://github.com/majd/ipatool))

***

### **Installing Apps**

* **Via Xcode**: Compile & run directly
* **From IPA**: Use `ideviceinstaller` (libimobiledevice) or Cydia Impactor or xcode
* **From App Store**: Direct install (limited debug features)
