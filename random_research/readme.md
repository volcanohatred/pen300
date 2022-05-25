# For random tools/ pocs

## tornado 

https://www.kitploit.com/2022/05/tornado-anonymously-reverse-shell-over.html?m=1

Tornado is implements tor network with metasploit-framework tool and msfvenom module, you can easily create hidden services for your localhost .onion domain without portforwarding. If you have experience different remote administration tools, probably you know you need forward port with virtual private network or ngrok but in this sense with tornado, the tor network offers the possibility of making services in a machine accessible as hidden services without portforwarding, by taking advantage of the anonymity it offers and thereby preventing the real location of the machine from being exposed.

tornado can do

create hidden service with tor network
generate cross platform msfvenom payload with fully undetectable shellcode execution not shikata_ga_nai things
hidden service becomes available outside tor network and ready to reverse shell connection

https://github.com/samet-g/tornado/blob/main/tornado/core/undetectable.py

The undetectable payload used was xor and uptick

s
