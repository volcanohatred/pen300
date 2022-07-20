<<<<<<< HEAD
# Bypassing Network filters

what all needs to be bypassed?

1. dns - name resolution
2. internal firewall - limits based on IP address and port number
3. ssl inspection 
4. proxy server or an IDS
5. external firewall

requires a fill lab setup

windows machine named client
ubnut linux machine named ubuntu
then we will be sitting at kali linux the attacker interface

# Lab setup

The lab includes a Windows 10 machine named client and an Ubuntu Linux machine named 
ubuntu. The Ubuntu system serves as an edge defense machine and will handle all defensive 
tasks. 

It’s running DNS for name resolution, an Nginx494 web server, and Snort,
495 which is set to 
capture all network traffic. Most of the Snort rules are turned off for now, but a few custom rules 
that enable basic filtering are installed.

From an external perspective, we can SSH to the Ubuntu system from our Kali machine. The 
Windows 10 machine is behind the Ubuntu machine, which means we can’t access it directly. 
However, a port forwarding rule forwards RDP requests so we can RDP to the Windows client by 
connecting to the Ubuntu machine on TCP port 3389.

we need to use domain names to move to our c2 server

# DNS filters

They compare requested domains to a blocklist of malicious domain names. - malwaredomainnamelist

it can reroute malicious traffic to a sinkhole - for more ananlysis or simpley drop it

![](20220720150855.png)  

OpenDNS blocks phishing sites

```
└─$ sudo bash -c "echo nameserver 8.8.8.8 > /etc/resolv.conf"
[sudo] password for kali: 
                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ nslookup www.internetbadguys.com
Server:         8.8.8.8
Address:        8.8.8.8#53

Non-authoritative answer:
Name:   www.internetbadguys.com
Address: 146.112.255.155

                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ sudo bash -c "echo nameserver 208.67.222.222 > /etc/resolv.conf"
                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ nslookup www.internetbadguys.com
Server:         208.67.222.222
Address:        208.67.222.222#53

Non-authoritative answer:
Name:   www.internetbadguys.com
Address: 146.112.61.108
Name:   www.internetbadguys.com
Address: ::ffff:146.112.61.108

```

Ipvoid looks whether the ip is reputable or not

### 9.1.1.1 Exercises
1. Repeat the steps above to test OpenDNS blocking.
   checked
2. Obtain various domain reputation results with IPVoid.
    didnt work
# Dealing with DNS filters

we need to select a domain that appeasrs to be legitimate

new domain may seem logical however it may be categorized as a Newly seen domain. which affects the reputaion.

domain classification should not be webmail

we can host legitimate looking website on the domain and request recategorization

### 9.1.2.1 Exercise
1. Using OpenDNS, check the categorization of a couple of domains.
    cant find opendns portal

# Web Proxies

Simply put, web proxy servers accept and forward web traffic on behalf of a client, for example, a 
web browser. This is often done in a Network Address Translation (NAT) environment, in which 
the internal private source IP addresses511 are translated into Internet-routable addresses

>>>>>>> 3debc343679504361ce9d49bb1a566fcbc18f55d
