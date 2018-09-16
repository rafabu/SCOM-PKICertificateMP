' return a PropertyBag with PowerShell compatibility information

Option Explicit

SetLocale("en-us")

' create MOM Script API object
Dim oArgs, oAPI
Dim iEvent
Dim waID, agentComputer, storeName
Set oAPI = CreateObject("MOM.ScriptAPI")

'get the parameters from the management pack
Set oArgs = WScript.Arguments
iEvent = oArgs(0)
waID = oArgs(1)
agentComputer = oArgs(2)
storeName = oArgs(3)

'write event
oAPI.LogScriptEvent "TriggerTestEvent.vbs", CInt(iEvent), 0, "TriggerTestEvent.vbs started with " & vbCrLf & vbCrLf & _
"WriteAction ID: " & waId & vbCrLf & _
"Agent: " & agentComputer & vbCrLf & _
"Store: " & storeName

