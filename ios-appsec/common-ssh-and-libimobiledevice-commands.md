# Common SSH and libimobiledevice Commands

## SSH

```bash
# ssh connect (virtual device)
ssh root@10.11.1.1
# SSH Over SUB (physical device)
iproxy 2222 22
ssh root@localhost -p 2222
# List Directories
ls -la
# Change directory:
cd /var/mobile
# Find the application bundle directory of all (user) installed apps:
find /private/var/containers/Bundle/Application/ -name "*.app"
# Copy files from the device to your computer:
scp root@10.11.1.1:/etc/master.passwd ~/Downloads/
# Upload files to the iOS device:
scp ./payload.txt root@10.11.1.1:/var/mobile/Documents/
```

## libimobiledevice Tools <a href="#el_1726217532447_403" id="el_1726217532447_403"></a>

```bash
# device info 
ideviceinfo
# List installed apps
ideviceinstaller --list-apps
# Install an app (IPA):
ideviceinstaller --install ./DVIA-v2.ipa
# Uninstall an app:
ideviceinstaller --uninstall com.highaltitudehacks.DVIAswiftv2
# Create a full backup (with encryption enabled):
idevicebackup2 encryption on "[PASSWORD]"
idevicebackup2 backup --full ~/Backups/
# Restore a backup:
idevicebackup2 restore \
  --system \
  --settings \
  --password "[PASSWORD]" \
  ~/Backups/
# View backup information:
idevicebackup2 info ~/Backups/
# 4. idevicesyslog: View iOS System Logs
idevicesyslog
# Download a copy of all crash reports:
idevicecrashreport --keep ~/Reports/

```

## Automation

```bash
# Backup and Data Extraction Script
#!/bin/bash

BACKUP_PATH="$HOME/Device/Backups/"
EXTRACT_PATH="$HOME/Device/Data/"
APP_UID="5CAF9854-AE84-4ABB-A856-5DE570E96171"

# Create a backup
echo "Creating backup..."
idevicebackup2 backup "$BACKUP_PATH"

# Extract data from app directory
echo "Extracting data from app ($APP_UID)..."
scp -r root@10.11.1.1:/var/mobile/Containers/Data/Application/$APP_UID/ "$EXTRACT_PATH"
```
