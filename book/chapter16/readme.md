# active directory exploitation

The 
complexity of Active Directory object permissions, Kerberos delegation, and Active Directory trust 
in particular sets the stage for several interesting and often-neglected attack vectors that we will 
explore in this module

# AD object security security permissions
If AD permissions are set incorrectly, we may be able to exploit them to perform privilege 
escalation or lateral movement within the domain. In the following sections, we’ll discuss these 
securable object permissions and demonstrate how to enumerate and exploit them

# object permission theory

DACL - Descretionary access control list - access control entries. each ace determines if the obhject is allowed or denied.

if a deny ace comes before an allow ace the deny takes precedence
ace is stored according to Descriptor Definition Language SDDL

ex - `(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-1-0)`

which means - from https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks

https://docs.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights

```
AceType: 
A = ACCESS_ALLOWED_ACE_TYPE
Access rights:
RP = ADS_RIGHT_DS_READ_PROP
WP = ADS_RIGHT_DS_WRITE_PROP
CC = ADS_RIGHT_DS_CREATE_CHILD
DC = ADS_RIGHT_DS_DELETE_CHILD
LC = ADS_RIGHT_ACTRL_DS_LIST
SW = ADS_RIGHT_DS_SELF
RC = READ_CONTROL
WD = WRITE_DAC
WO = WRITE_OWNER
GA = GENERIC_ALL
Ace Sid: 
S-1-1-0
```

we can do it by loading poewrview and then using Get-ObjectACl
```powershell
$url = "https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerView/powerview.ps1"
$targetfolder = "./powerview.ps1"
Start-BitsTransfer -Source $url -Destination $targetfolder

Get-ObjectACl
```

COnvertFrom-SID method
`ConvertFrom-SID S-1-5-21-3776646582-2086779273-4091361643-553`

we can use manual SID conversion

```powershell
Get-ObjectAcl -Identity offsec -ResolveGUIDs | Foreach-Object {$_ | AddMember -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID 
$_.SecurityIdentifier.value) -Force; $_}
```

### 16.1.1.1 Exercises
1. Repeat the enumeration techniques with PowerView shown in this section.
2. Filter the output further to only display the ACE for the current user

# Abusing GenericAll




