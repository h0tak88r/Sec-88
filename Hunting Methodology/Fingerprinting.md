---
tags:
  - web_hunting
---

-  Port Scanning [https://github.com/nullt3r/jfscan](https://github.com/nullt3r/jfscan)
    
    ```bash
    # Before installation
    sudo apt install libpcap-dev
    sudo apt-get --assume-yes install git make gcc
    #masscan
    git clone <https://github.com/robertdavidgraham/masscan>
    cd masscan
    make
    sudo make install
    sudo setcap CAP_NET_RAW+ep /usr/bin/masscan
    sudo apt install python3 python3-pip
    # install jfscan
    git clone <https://github.com/nullt3r/jfscan.git>
    cd jfscan
    cd jfscan
    # incase of error running 
    export PATH="$HOME/.local/bin:$PATH"
    ```
    
- Waf Detect
    
    ```bash
    nuclei -l urls.txt -t nuclei_templates/waf
    sudo apt install wafw00f
    wafw00f -l urls.txt
    ```
- **[uncover](https://github.com/projectdiscovery/uncover)** >> discover exposed hosts on the internet. It is built with automation in mind, so you can query it and utilize the results with your current pipeline tools.
	```python
	# installation
	go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
	# configuration file 
	$HOME/.config/uncover/provider-config.yaml
	# usage
	uncover -q "test.com" -e censys,fofa,shodan
	```

