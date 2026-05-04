# Briefing: Intercepting Android Traffic via Mobile Data and Ngrok

### Executive Summary

This document outlines a technical methodology for intercepting Android mobile application traffic when a device is connected via mobile data (cellular) rather than a shared local network. Standard proxy configurations fail in these scenarios because the mobile device and the interception tool (Burp Suite) reside on different networks. The solution involves establishing an internet-accessible tunnel using Ngrok to bridge this gap, allowing remote traffic to reach a local proxy listener. Key steps include configuring a TCP tunnel, utilizing a mobile proxy management application, and installing CA certificates for HTTPS inspection.

### The Challenge of Mobile Data Interception

Traditional mobile application security testing typically relies on the device and the workstation being on the same Wi-Fi network. However, when a device utilizes mobile data:

* **Network Isolation**: The device operates on a cellular network that cannot natively "see" a local proxy listener (e.g., Burp Suite) running on a private IP address.
* **Connectivity Barriers**: Standard proxy configurations (IP and Port) are unreachable over the public internet without specific routing.
* **Solution Requirement**: An internet-accessible tunnel is necessary to route traffic from the device across the web to the local testing environment.

### Technical Setup: Burp Suite and Ngrok

The interception process requires a stable local proxy and a tunneling service to expose that proxy to the internet.

1. **Local Proxy Configuration**
   1. Tool: Burp Suite.
   2. Action: Launch the application and ensure the proxy listener is active.
   3. Default Listener: Usually set to **`127.0.0.1:8080`**. This can be verified under the Proxy > Options tab.
2. **Ngrok Tunneling**

Ngrok is used to create a secure TCP tunnel to the local machine.

* Authentication: The installation must be authenticated using a unique auth token:
  * Command: `ngrok config add-authtoken`
* Tunnel Creation: To link Ngrok to the Burp Suite listener, a TCP tunnel is established:
  * Command: `ngrok tcp 8080`
* Endpoint Generation: Once the tunnel is active, Ngrok provides a public endpoint URL and port (e.g., `0.tcp.ngrok.io:12345`). This endpoint is used by the mobile device to reach the local Burp Suite instance.

### Android Device Configuration

Because Android’s native settings may not easily handle complex proxy routing over cellular data, third-party management tools and certificate installations are required.

1. **Proxy Management Application**

A proxy management application (such as Super Proxy) must be installed from the Play Store. This allows the user to define specific proxy profiles that function over cellular connections.

2. **Profile Parameters**

Within the proxy application, a new profile must be created using the data provided by the Ngrok tunnel:

Parameter Value Type HTTP Host Your specific Ngrok hostname (e.g., **`0.tcp.ngrok.io`**) Port Your specific Ngrok port (e.g., **`12345`**)

The profile must be activated while the device is connected to cellular data.

3. **HTTPS Inspection (CA Certificate)**

Intercepting encrypted HTTPS traffic requires the installation of the Burp Suite CA certificate on the Android device.

* Download: Navigate to http://burp through the device browser while the proxy is active.
* Installation: The certificate must be installed as a trusted certificate on the device's root. The exact process for installation varies depending on the Android version and the manufacturer.

### Verification and Alternative Solutions

**Testing the Configuration**

To confirm the setup is functional:

1. Navigate to the HTTP History tab in Burp Suite.
2. Generate network activity on the Android device (e.g., browsing or using apps).
3. Successful configuration is confirmed if traffic logs begin appearing in Burp Suite.

**Private and Internal Alternatives**

While Ngrok is effective for general use, it may not be suitable for internal corporate environments or highly sensitive projects. In such cases, the following alternatives are recommended:

* Self-hosted Solutions: Deploying proprietary tunneling infrastructure.
* VPN Tunnels: Setting up a private VPN using OpenVPN or WireGuard to create a secure, controlled path for traffic interception.
