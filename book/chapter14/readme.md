# Linux Lateral Movement

we need to configure our /etc/hosts file first with

```dotnetcli
controller: 192.168.120.40
• linuxvictim: 192.168.120.45
• dc01.corp1.com: 192.168.120.5
```

# lateral movement with ssh

ssh private kes are exellent opportunity for lateral movement

# ssh keys

ssh kes have permission set to 600

private keys are named as id_rsa by default 

we can use `find /home/ -name "id_rsa"`

if nothing comes up then there might be no keys with admin permission

```
└─$ find /home/ -name "id_rsa"
/home/kali/.ssh/id_rsa
```

It’s not uncommon for users to copy their keys to a different location than the default 
/home/username/.ssh/ folder or to have copies of keys with different names. Because of this, 
we’ll inspect the /home directory once again and browse other user’s files with our elevated 
privileges.
If we examine the /home/linuxvictim directory, we note that a private key with an unconventional 
name, svuser.key, is stored there.




