' return a PropertyBag with PowerShell compatibility information

SetLocale("en-us")

' create MOM Script API object
Dim oAPI, isInstalled
Set oAPI = CreateObject("MOM.ScriptAPI")
isInstalled = "True"

' create Registry object
Dim oReg, key, value, runtimeVersion, runtimeVersionValue, psCompatibleVersion, psCompatibleVersionValue
' suppress error
On Error Resume Next
Set oReg = CreateObject("WScript.Shell")
key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Powershell\3\PowerShellEngine\"
runtimeVersionValue = "RunTimeVersion"
psCompatibleVersionValue = "PSCompatibleVersion"
runtimeVersion = oReg.RegRead(key & runtimeVersionValue)
psCompatibleVersion = oReg.RegRead(key & psCompatibleVersionValue)
If Err.Number <> 0 Then
	' registry does not exist. No Powershell V3 seems to be installed - check V1/2
	Err.Clear
	key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Powershell\1\PowerShellEngine\"
	runtimeVersionValue = "RunTimeVersion"
	psCompatibleVersionValue = "PSCompatibleVersion"
	runtimeVersion = oReg.RegRead(key & runtimeVersionValue)
	psCompatibleVersion = oReg.RegRead(key & psCompatibleVersionValue)
	If Err.Number <> 0 Then
		' registry does not exist. No Powershell V1/2 seems to be installed
		Err.Clear
		isInstalled = "False"
		runtimeVersion = ""
		psCompatibleVersion = ""
		WScript.Echo "No PowerShell is installed."
	End if
End If
' resume error
On Error Goto 0

Dim oPropertyBag
Set oPropertyBag = oAPI.CreatePropertyBag()
Call oPropertyBag.AddValue("PowerShell_Installed", isInstalled)
Call oPropertyBag.AddValue("PowerShell_Runtime", CStr(runtimeVersion))
Call oPropertyBag.AddValue("PowerShell_Compatibility", CStr(psCompatibleVersion))
Call oAPI.Return(oPropertyBag)

		