# Mac OSX TTPs

## Enumeration

### Gathering System Information Using IOPlatformExpertDevice

The ioreg command allows interaction with the I/O Kit registry, and the -c flag specifies the class of devices to list. The IOPlatformExpertDevice class provides information about the platform expert, which includes various system attributes. The -d flag specifies the depth of the search within the device tree.

```sh
ioreg -c IOPlatformExpertDevice -d 2
```

### Exploring Application Bundles

Applications on macOS are stored in the /Applications directory. Each application is bundled as a .app file, which is actually a directory with a specific layout. Key components of an application bundle include:

  1. Info.plist: This file contains application-specific configuration, entitlements, tasks, and metadata.

  2. MacOS: This directory contains the Mach-O executable.

  3. Resources: This directory includes icons, fonts, and images used by the application.

```sh
# List Applications
ls /Applications

cd /Applications/Lens.app
ls -R
```

### Basic System Enumeration

Versions:

```sh
❯ sw_vers
ProductName:		macOS
ProductVersion:		14.5
BuildVersion:		23F79
```

Environment Variables:

```sh
❯ printenv
LANG=en_US.UTF-8
PWD=/Users/rosesecurity
```

Home Folders:

```sh
❯ ls -ma ~/
.!48082!pack-8ad6a5dc9b062d5e0e8d0bd9fa08146698e612e9.rev, .!48110!index, .., .CFUserTextEncoding, .DS_Store, .Trash, .aws,
.azure, .bash_history, .bashrc, .boto,
```

### Users

The three types of MacOS users are:

  - **Local Users** — Managed by the local OpenDirectory service, they aren’t connected in any way to the Active Directory

  - **Network Users** — Volatile Active Directory users who require a connection to the DC server to authenticate

  - **Mobile Users** — Active Directory users with a local backup for their credentials and files

```sh
# User and Group Enumeration

dscl . ls /Users
dscl . read /Users/[username]

dscl . ls /Groups
dscl . read /Groups/[group]

# Domain Enumeration
dsconfigad -show
```

### Network Services

```sh
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```

### SMB Shares

```sh
# SMB share enumeration
smbutil view -G //servername.domain
sharing -l
smbutil statshares -a
```

### AFP Shares

```sh
# AFP share enumeration
dns-sd -B _afpovertcp._tcp
nmap -p 548 --script afp-showmount --script-args afp.username=yourusername,afp.password=yourpassword yourserveraddress
sudo sharing -l
```

### SSH Scanning

Browse for all SSH services that are currently advertised on the local network

```sh
dns-sd -B _ssh._tcp
```

