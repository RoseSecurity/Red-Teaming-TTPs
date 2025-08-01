# :cloud: Enum_AzureSubdomains: Anonymously Enumerating Azure Services

<p align="center">
  <img alt="AzureDoggo" src="https://user-images.githubusercontent.com/72598486/216847358-a72ce9e8-7d25-4b27-b386-f21d339580fa.png">
</p>

Microsoft makes use of a number of different domains and subdomains for each of their Azure services. From SQL databases to SharePoint drives, each service maps to its respective domain/subdomain, and with the proper toolset, these can be identified through DNS enumeration to yield information about the target domain's infrastructure. ```enum_azuresubdomains.rb``` is a Metasploit module for enumerating public Azure services by validating legitimate subdomains through various DNS record queries. This cloud reconnaissance module rapidly identifies API services, storage accounts, key vaults, databases, and more! Expedite your cloud reconnaissance phases with ```enum_azuresubdomains.rb```.

## Domains and Associated Services:

| Domain | Associated Service |
| --- | --- |
| azurewebsites.net | App Services |
| scm.azurewebsites.net | App Services - Management |
| p.azurewebsites.net | App Services |
| cloudapp.net | App Services |
| file.core.windows.net | Storage Accounts-Files |
| blob.core.windows.net | Storage Accounts-Blobs |
| queue.core.windows.net | Storage Accounts-Queues |
| table.core.windows.net | Storage Accounts-Tables |
| redis.cache.windows.net | Databases-Redis |
| documents.azure.com | Databases-Cosmos DB |
| database.windows.net | Databases-MSSQL |
| vault.azure.net | Key Vaults |
| onmicrosoft.com | Microsoft Hosted Domain |
| mail.protection.outlook.com | Email |
| sharepoint.com | SharePoint |
| azureedge.net | CDN |
| search.windows.net | Search Appliance |
| azure-api.net | API Services |

***NOTE: Enumerating existing Azure subdomains may be handy for anyone looking to conduct subdomain takeovers. Subdomain takeovers are typically done the other way around (finding a domain that’s no longer registered or in use), but by preemptively discovering the domains, and keeping tabs on them for later, you may be able to monitor for potential subdomain takeovers.***

# Demo:

https://user-images.githubusercontent.com/72598486/217250582-eada89ee-ac4a-41c3-8421-314aa8e75bca.mov

# Install:

Download repository:

```
$ mkdir Enum_AzureSubdomains
$ cd Enum_AzureSubdomains/
$ sudo git clone https://github.com/RoseSecurity/Enum_AzureSubdomains.git
```

Usage:

To load the script into Metasploit:

```
# Create directory for module
$ mkdir -p ~/.msf4/modules/auxiliary/gather
# Move script into folder
$ mv enum_azuresubdomains.rb ~/.msf4/modules/auxiliary/gather
```

Fire up Metasploit:

```
# Quietly start Metasploit and reload all modules
$ msfconsole -q -x 'reload_all'
# Use module
msf6> use auxiliary/gather/enum_azuresubdomains
```

If you encounter any errors, check the following log:

```
$ tail ~/.msf4/logs/framework.log
```

