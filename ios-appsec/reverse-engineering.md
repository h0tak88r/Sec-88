# Reverse Engineering

## Decompiling the App <a href="#el_1727115917528_340" id="el_1727115917528_340"></a>

```bash
# IPSW Injstall
brew install blacktop/tap/ipsw
ipsw --help

# Install Swift
MacOS -> just install xcode
sudo apt install -y curl
curl -L https://swiftlygo.xyz/install.sh | bash
sudo swiftlygo install latest
swift --help

# Extract the IPA File
unzip ./DVIA-v2.ipa

# Locate the App Binary
./Payload/DVIA-v2.app/DVIA-v2

# Dumping Objective-C Classes Using class-dump
ipsw class-dump ./Payload/DVIA-v2.app/DVIA-v2 --headers -o ./class_dump

# Dumping Swift Classes Using swift-dump
ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 > ./swift_dump_mangled.txt
ipsw swift-dump ./Payload/DVIA-v2.app/DVIA-v2 --demangle > ./swift_dump_demangled.txt
```

### Automation for Decompiling

```bash
#!/bin/bash

# Check if an IPA file was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <path_to_ipa_file>"
  exit 1
fi

IPA_FILE="$1"

# Check if the IPA file exists
if [ ! -f "$IPA_FILE" ]; then
  echo "[@] Error: IPA file not found!"
  exit 1
fi

# Get the app name from the IPA file
APP_NAME="$(basename ""$IPA_FILE"" .ipa)"
OUTPUT_DIR="$(dirname ""$IPA_FILE"" | xargs readlink -f)"

# Create output directory
OUTPUT_DIR="$OUTPUT_DIR/$APP_NAME"
mkdir -p "$OUTPUT_DIR"

# Unzip the IPA contents
UNZIP_DIR="$OUTPUT_DIR/_extracted"
echo "[*] Extracting IPA contents..."
mkdir -p "$UNZIP_DIR"
unzip -q "$IPA_FILE" -d "$UNZIP_DIR"

# Locate the .app directory
APP_PATH=$(find "$UNZIP_DIR" -name "*.app" -type d)

if [ -z "$APP_PATH" ]; then
  echo "[@] No .app found in $UNZIP_DIR, exiting..."
  exit 1
fi

BINARY="$APP_PATH/$(basename ""$APP_PATH"" .app)"

# Check if the binary exists (file without an extension in the .app folder)
if [ ! -f "$BINARY" ]; then
  echo "[@] No binary found in $APP_PATH, exiting..."
  exit 1
fi

# Create directories for class dumps
CLASS_DUMP_OUTPUT="$OUTPUT_DIR/class_dump"
SWIFT_DUMP_OUTPUT="$OUTPUT_DIR/swift_dump"
mkdir -p "$CLASS_DUMP_OUTPUT"
mkdir -p "$SWIFT_DUMP_OUTPUT"

# Dump Objective-C classes using class-dump
echo "[*] Dumping Objective-C classes for $APP_NAME..."
ipsw class-dump "$BINARY" --headers -o "$CLASS_DUMP_OUTPUT"

# Dump Swift classes using swift-dump
echo "[*] Dumping Swift classes for $APP_NAME..."
ipsw swift-dump "$BINARY" > "$SWIFT_DUMP_OUTPUT/$APP_NAME-mangled.txt"
ipsw swift-dump "$BINARY" --demangle > "$SWIFT_DUMP_OUTPUT/$APP_NAME-demangled.txt"

echo "[+] Decompilation completed for $APP_NAME"
```
