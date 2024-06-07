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
