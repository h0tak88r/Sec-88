---
description: https://www.automatetheplanet.com/adb-cheat-sheet/
---

# ADB Commands

```bash
### adb commands
adb devices                            	         # list running emulators
adb -s 127.0.0.1:6555 shell
adb -s 127.0.0.1:6555 pull path/to/file.ext ./   # pull file from the emulator 
adb root				     
adb log						 # Android log
adb kill-server                                  # Kill server
adb sart-server                                  # Start server
adb devices
adb reboot
adb help
adb shell install <apk>                         # install app
adb shell install <path>                        # (install app from phone path)
adb shell install -r <path>                     # (install app from phone path)
adb shell uninstall <name>                      # remove the app)
adb get-statе                                   # (print device state)
adb get-serialno                                # (get the serial number)
adb shell dumpsys iphonesybinfo                 # (get the IMEI)
adb shell netstat                               # (list TCP connectivity)
adb shell pwd                                   # (print current working directory)
adb shell dumpsys battery                       # (battery status)
adb shell pm list features                      # (list phone features)
adb shell service list                          # (list all services)
adb shell dumpsys activity <package>/<activity> # (activity info)
adb shell ps                                    # (print process status)
adb shell wm size                               # (displays the current screen resolution)
dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp' # (print current app's opened activity)
adb logcat [options] [filter] [filter]          # (view device log)
adb bugreport                                   # (print bug reports)
```

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>
