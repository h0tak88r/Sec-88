> **Digital Ocean**

- `ssh root@134.122.78.53`
- `password: mOsa@d_4321a`

> **Google Cloud Shell**

- `gcloud cloud-shell ssh --authorize-session`

> **GitHub CLI**

- `gh codespace ssh`

> **Segfault**

```bash
cat >~/.ssh/id_sf-lulz-segfault-net <<'__EOF__'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBBpNSZc8Zn35jpoxbK03ewXH8YhuG2z6m3RcydTnWC1AAAAIjbUJ7a21Ce
2gAAAAtzc2gtZWQyNTUxOQAAACBBpNSZc8Zn35jpoxbK03ewXH8YhuG2z6m3RcydTnWC1A
AAAEC8FtXepDOXBZV/nBTKMOFCsm8kqSpLpVwjjquJPeWsJEGk1JlzxmffmOmjFsrTd7Bc
fxiG4bbPqbdFzJ1OdYLUAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
__EOF__
cat >>~/.ssh/config <<'__EOF__'                                                
host exhaustnoise                                                              
    User root
    HostName lulz.segfault.net
    IdentityFile ~/.ssh/id_sf-lulz-segfault-net
    SetEnv SECRET=SeoMucKswbWWwHrtiFfHkRVG
__EOF__
chmod 600 ~/.ssh/config ~/.ssh/id_sf-lulz-segfault-net
------------------------
ssh  exhaustnoise
```
