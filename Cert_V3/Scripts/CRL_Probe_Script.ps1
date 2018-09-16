param([string]$storeName = "CA", [string]$arsPowerShellSnapInPath, [string]$debugParam)

#####$arsPowerShellSnapInPath = "C:\Temp\PKI_Certificate_V2\PKI_Certificate_V2\Resources\Quest.ActiveRoles.ArsPowerShellSnapIn.dll"

# Get access to the scripting API
$scomAPI = new-object -comObject "MOM.ScriptAPI"

#PoSh 2.0 was shipped with 2008R2/Win7. In order to have as little dependency on later updates
#     as possible this script only uses (in parts inconvinient) 2.0 cmdlets
$minimalPSVersion = "2.0"

#lookup for certificates snap-in friendly names (in english only)
$storeNameTable = @{"AuthRoot" = "Third-Party Root Certification Authorities";
	"CA" = "Intermediate Certification Authorities";
	"Disallowed" = "Untrusted Certificates";
	"My" = "Personal";
	"REQUEST" = "Certificate Enrollment Requests";
	"Root" = "Trusted Root Certification Authorities";
	"SmartCardRoot" = "Smart Card Trusted Roots";
	"Trust" = "Enterprise Trust";
	"TrustedDevices" =  "Trusted Devices";
	"TrustedPeople" = "Trusted People";
	"TrustedPublisher" = "Trusted Publisher"}                                                                                                         


if( ($PSVersionTable.PSCompatibleVersions) -contains $minimalPSVersion)
	{
	Write-Host Powershell installed: ( $PSVersionTable.PSVersion.ToString() )
	Write-Host      It is compatible with version $minimalPSVersion required by this script
	
	Import-Module $arsPowerShellSnapInPath -DisableNameChecking
	
	if ( Get-Module | where {$_.Name -eq "Quest.ActiveRoles.ArsPowerShellSnapIn"})
		{
		# enumerate local CRLs
		Get-QADLocalCertificateStore -StoreLocation LocalMachine -StoreName $storeName | Get-QADCertificateRevocationList | % { `
			#build a SCOM property bag
			$objCRLBag = $scomAPI.CreatePropertyBag() 
		
			$objCRLBag.AddValue("InstanceType", "CRL")
			$objCRLBag.AddValue("CRLVersion", [string]$_.Version)
			$objCRLBag.AddValue("CRLSigAlg", [string]$_.SignatureAlgorithm.FriendlyName)
			$objCRLBag.AddValue("CRLIssuedBy", [string]$_.Issuer)
			$objCRLBag.AddValue("CRLThisUpdate", [string]$_.EffectiveDate.ToUniversalTime())
			$objCRLBag.AddValue("CRLNextUpdate", [string]$_.NextUpdate.ToUniversalTime())
			$objCRLBag.AddValue("CRLEntries", [int]$_.Entries.Count)
			#CERT_SHA1_HASH_PROP_ID is not exposed, hence build a key using the isuer instead
			$objCRLBag.AddValue("CRLThumbprint", [string]$_.Issuer.GetHashCode())
			
			$objCRLBag.AddValue("CRLDaysUntilUpdate", [double](($_.NextUpdate - (Get-Date)).Days))
			if ((($_.NextUpdate - (Get-Date)).TotalDays) -le 0) {$objCRLBag.AddValue("CRLNeedsUpdate", "True")}
			else  {$objCRLBag.AddValue("CRLNeedsUpdate", "False")}
			
			$objCRLBag
			}
		}
	else
		{
		Write-Host Failed to load Quest.ActiveRoles.ArsPowerShellSnapIn from `t`t`t`t`t`t`t`t -BackgroundColor red 
		Write-Host `t path  $arsPowerShellSnapInPath `t -BackgroundColor red
		exit
		}

	}
else
	{
	Write-Host Powershell installed: $PSVersionTable.PSVersion.ToString() `t`t`t`t`t`t`t`t -BackgroundColor red 
	Write-Host `tIt is not compatible with version $minimalPSVersion required by this script `t -BackgroundColor red
	exit
	}
