# Port Redirection and Tunneling

### SSH Local Port Forwarding

* **On Attacker Machine:**
  *   Use the following command to establish local port forwarding:

      ```bash
      sudo ssh -L localhost:local-port:target:remote-port user@mediator
      ```
  * Replace `localhost`, `local-port`, `target`, `remote-port`, `user`, and `mediator` with appropriate values.
  * This redirects traffic from the local machine's `local-port` to the `target:remote-port` through the `mediator` machine.

### SSH Remote Port Forwarding

* **On Victim Machine:**
  *   Use the following command to establish remote port forwarding:

      ```bash
      sudo ssh -R 8080:127.0.0.1:80 kali@192.168.1.15
      ```
  * Replace `8080`, `127.0.0.1:80`, `kali`, and `192.168.1.15` with appropriate values.
  * This redirects traffic from the victim machine's `127.0.0.1:80` to the attacker's machine on port `8080`.

### SSH Dynamic Port Forwarding

*   Use the following command to establish dynamic port forwarding:

    ```bash
    ssh -D 8080 user@ip
    ```

    * Replace `8080`, `user`, and `ip` with appropriate values.
    * This creates a dynamic SOCKS proxy on the local machine, redirecting traffic through the specified SSH server.
