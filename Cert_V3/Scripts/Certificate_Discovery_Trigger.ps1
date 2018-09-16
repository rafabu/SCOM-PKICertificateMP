#Trigger OnDemand Discovery for Certificate MP
#
#       Will run on management server (SCOM Command Shell) side as a WriteAction
#       following certificate or store handling tasks
#
#		Parameters
#			$wfOriginatorComputerName			Name of the HealthService
#			$wfOriginatorStoreName              Name of the Certificate Store (key)
#
# Version 1.0 - 18. May 2015 - initial            - Raphael Burri - raburri@bluewin.ch
#
Param ($wfOriginatorComputerName = 'devscom12-1.mgmtdom.momdev',
	$wfOriginatorStoreName = 'My',
	$debug = "False")

#variables
$computerName ='localhost'
	
#SCOM safe reformatting of boolean override (that are actually strings); default to True unless parameter is string "False"
if (!$debug -eq "False") {$debug = "True"}
#SCOM API & discovery data
$scomAPI = new-object -comObject 'MOM.ScriptAPI'
if ($debug -eq 'true') { $scomAPI.LogScriptEvent("Certificate_Discovery_Trigger.ps1", 130 , 4, "
Starting script with the folowing parameters:

wfOriginatorComputerName: " + $wfOriginatorComputerName + "
wfOriginatorStoreName: " + $wfOriginatorStoreName) }

#load SCOM module
if (!(Get-Module -Name OperationsManager)) {import-module OperationsManager}
#import-module operationsmanager
#load SDK & connect to allow more selectiv selecting of monitoring objects
$error.Clear()
$ErrorActionPreference = "SilentlyContinue"
#SCOM 2012
[void][System.Reflection.Assembly]::Load("Microsoft.EnterpriseManagement.Core, Version=7.0.5000.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35")
[void][System.Reflection.Assembly]::Load('Microsoft.EnterpriseManagement.OperationsManager, Version=7.0.5000.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35')
$scomLevel = 7
if ($error) {
    $error.Clear()
    #SCOM 2007
    [void][System.Reflection.Assembly]::Load("Microsoft.EnterpriseManagement.Core, Version=6.0.4900.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35")
    [void][System.Reflection.Assembly]::Load("Microsoft.EnterpriseManagement.OperationsManager, Version=6.0.4900.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35")
    $scomLevel = 6 
}
$ErrorActionPreference = "Continue"

try{ $scomMG = [Microsoft.EnterpriseManagement.ManagementGroup]::Connect($computerName) }
catch {}
if (($scomMG) -and ($scomMG.IsConnected -eq $true)) {
	Write-Host ("Connected to SCOM Management Group: " + $scomMG.Name + "`n     on Computer: " + $ComputerName + ". SCOM Level " + $scomLevel)
	if ($debug -eq 'true') { $scomAPI.LogScriptEvent("Certificate_Discovery_Trigger.ps1", 131, 4, "Connected to SCOM Management Group: " + $scomMG.Name + "`n     on Computer: " + $ComputerName + ". SCOM Level " + $scomLevel) }
}
else {
	Write-Host -BackgroundColor Yellow ("Failed to connect to SCOM Management Group on Computer: " + $ComputerName + ". SCOM Level " + $scomLevel)
	$scomAPI.LogScriptEvent("Certificate_Discovery_Trigger.ps1", 132, 2, ("Failed to connect to SCOM Management Group on Computer: " + $ComputerName + ". SCOM Level " + $scomLevel + "
	
Ending script without taking any action."))
	exit
}


$hsClass = $scomMG.GetMonitoringClasses('Microsoft.SystemCenter.HealthService')[0]
$storeClass = $scomMG.GetMonitoringClasses('SystemCenterCentral.Utilities.Certificates.CertificateStore')[0]

$hsObjectCriteriaString = "DisplayName='" + $wfOriginatorComputerName + "'"
$hsObjectCriteria = new-object Microsoft.EnterpriseManagement.Monitoring.MonitoringObjectCriteria($hsObjectCriteriaString, $hsClass)
$hsObject = ($scomMG.GetMonitoringObjects($hsObjectCriteria))[0]

$storeObjectCriteriaString = "Name='" + $wfOriginatorStoreName + "' AND Path='" + $wfOriginatorComputerName + "'"
$storeObjectCriteria = new-object Microsoft.EnterpriseManagement.Monitoring.MonitoringObjectCriteria($storeObjectCriteriaString, $storeClass)
$storeObject = ($scomMG.GetMonitoringObjects($storeObjectCriteria))[0]

$discoveryCriteria = [Microsoft.EnterpriseManagement.Configuration.ManagementPackDiscoveryCriteria]"Name='SystemCenterCentral.Utilities.Certificates.LocalScriptProbe.NonRootCertificate.Discovery' OR 
Name='SystemCenterCentral.Utilities.Certificates.LocalScriptProbe.RootCertificate.Discovery' OR 
Name='SystemCenterCentral.Utilities.Certificates.LocalScriptProbe.SelfSignedCertificate.Discovery' OR 
Name='SystemCenterCentral.Utilities.Certificates.LocalScriptProbe.CRL.Discovery'"
$discoveries = $scomMG.GetMonitoringDiscoveries($discoveryCriteria)

$taskCriteria = [Microsoft.EnterpriseManagement.Configuration.ManagementPackTaskCriteria]"Name='Microsoft.SystemCenter.TriggerOnDemandDiscovery'"
$task = ($scomMG.GetMonitoringTasks($taskCriteria))[0]

if (($hsObject -ne $null) -and ($storeObject -ne $null)) {
	#evaluate overrides; only run discovery if it is enabled in the context of target
	foreach ($discovery in $discoveries) {
		$discoveryEnabled = $discovery.Enabled
		
		$discoveryOverrideResults =  Get-SCOMOverrideResult -Discovery $discovery -Instance $storeObject |  where {$_.Override.Key -eq 'Enabled'}
	
		foreach ($discoveryOverrideResult in $discoveryOverrideResults) {
			$discoveryEnabled = $discoveryOverrideResult.Override.Value.EffectiveValue
		}
		
		if ($discoveryEnabled -eq 'True') {
			Write-Host Discovery is enabled on target $storeObject.Path \ $storeObject.Name: $discovery.DisplayName
			#trigger discovery via task
			$taskOverride = @{"DiscoveryId"=$discovery.Id.ToString(); "TargetInstanceId"=$storeObject.Id.ToString()}
			Write-Host -BackgroundColor Yellow Discovery: $discovery.Id.ToString()
			Write-Host -BackgroundColor Yellow Target: $storeObject.Id.ToString()
			
			$taskInstance = Start-SCOMTask -Task $task -Instance $hsObject -Override $taskOverride
			
			Write-Host `tTriggered `' $task.DisplayName `' task for this discovery and target
			if ($debug -eq 'true') { $scomAPI.LogScriptEvent("Certificate_Discovery_Trigger.ps1", 133, 4, "Triggered task '" + $task.DisplayName + "' for
			
Discovery: " + $discovery.Name + "
Target: " + $storeObject.Path + "\" + $storeObject.Name) }
		}
		else {
			Write-Host Discovery is disabled on target $storeObject.Path \ $storeObject.Name: $discovery.DisplayName
			if ($debug -eq 'true') { $scomAPI.LogScriptEvent("Certificate_Discovery_Trigger.ps1", 134, 4, "Discovery is disabled on target either completely or via an override.
Not triggering task.
			
Discovery: " + $discovery.Name + "
Target: " + $storeObject.Path + "\" + $storeObject.Name) }
		}
	}
}