#
# Enumerate certificates and CRLs in windows certificate stores
#		Returns SCOM property bags
#
#		P/Invoke on cert32.dll was required as .NET does not currently
#		feature an object for CRLs nor for advanced certificate stores (e.g. WinNT service based).
#
#		System requirements: Powershell >= 2.0 / .NET >= 2.0
#
#		Ignores RevocationStatusUnknown and OfflineRevocation (treated as valid)
#
#		Parameters
#			$storename			e.g. My
#			$storeProvider		SystemRegistry | System | File | LDAP
#			$storeType			LocalMachine | CurrentUser | Services | Users
#			$revocationFlag		EntireChain | ExcludeRoot | EndCertificateOnly
#			$revocationMode		Online | Offline | NoCheck
#			$verificationFlags  ...
#			$subjectIncludeRegEx
#			$issuerIncludeRegEx
#           $subjectExcludeRegEx
#			$issuerExcludeRegEx
#     $enhKeyUseIncludeRegEx RegEx to include certificates with a specific enhanced key usage OID
#			$enhKeyUseExcludeRegEx RegEx to exclude certificates with a specific enhanced key usage OID
#			$templateIncludeRegEx
#			$templateExcludeRegEx
#			$expiryThresholdDays
#			$debugParam
#
# Version 1.0 - 23. December 2013 - initial            - Raphael Burri - raburri@bluewin.ch
# Version 2.0 - 25. March 2014 	  - Self signed option - Raphael Burri - raburri@bluewin.ch
# Version 3.0 - 27. March 2014    - exception when calling PrtToStructure(InPtr, Type) on PoSh >= 3.0. KB2909958 describes a
#								 	workaround. 		- Raphael with a lot of help & coffee by Marc (MoW) and Joel (Jaykul)
# Version 3.1 - 28. March 2014    - open stores read only
# Version 3.2 - 11. June 2014     - skip certificates based on Enhanced Key Usage (napHealthyOid etc.)
# Version 4.0 - 04. July 2014     - filter certs & crl based on subject & issuer inside the script instead
#                                   of outside.
# Version 5.0 - 20. Feb 2015     - assure "Subject" can not be an empty string
#									added CertificateTemplate as a property and ex- & include RegEx
#									verbose output to deal with issues on the certificate's chain
#									filter "unknown error" from StatusMessage (PoSh 2.0)
# Version 5.1 - 07. May 2015	- add $expiryThresholdDays parameter to allow overriding when certificates
#									should be reported in views and reports
# Version 5.2 - 30. July 2015	- fix localized detection of template name
# Version 6.0 - 06. September 2018	- Add-Type modifications / add EKU to property bag / add EKU include filter
#
#
#	CRL bits originally provided by and included with the approval of Vadims Podāns - vpodans@sysadmins.lv
# 								http://www.sysadmins.lv/CategoryView,category,PowerShell,6.aspx
#

#region parameters
param([string]$storeName = "My",
  [string]$storeProvider = "SystemRegistry",
  [string]$storeType = "LocalMachine",
  [string]$revocationFlag = "EntireChain",
  [string]$revocationMode = "Online",
  [string]$verificationFlags = "IgnoreCertificateAuthorityRevocationUnknown,IgnoreEndRevocationUnknown",
  [string]$subjectIncludeRegEx = "^.*$",
  [string]$issuerIncludeRegEx = "^.*$",
  [string]$subjectExcludeRegEx = "^$",
  [string]$issuerExcludeRegEx = "^$",
  [string]$enhKeyUseIncludeRegEx = "^(|.+)$",
  [string]$enhKeyUseExcludeRegEx = "\n",
  [string]$templateIncludeRegEx = "^(|.+)$",
  [string]$templateExcludeRegEx = "\n",
  [int]$expiryThresholdDays = 31,
  [string]$ignoreSupersededCert = "true",
  [string]$debugParam = "true")
#endregion


#region just examples and placeholders for debug
#storeName: fullpath or just name. E.g.: "My" / c:\SOMEHWRE\store.bin / "WinNTServiceName\MY" etc...
#storeProvider: System (a summary map) / SystemRegistry (really is in registry) / File / LDAP
#storeType: LocalMachine / CurrentUser / Services / Users

#$storeName = "My"
#$debugParam = "true"
#$storeName = "aspnet_state\My"
#$storeProvider = "System"
#$storeProvider = "LDAP"
#endregion

#region variables and constants
# get script name
# SCOM agent calls them dynamically, assigning random names
#$scriptName = $MyInvocation.MyCommand.Name
$scriptName = "Certificate_Verify_Script_V5.ps1"
$userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#parameter from string (override param from SCOM) to boolean
if ($debugParam -eq 'true') { $debugScript = $true }
else { $debugScript = $false }
if ($ignoreSupersededCert -eq "true") { $ignoreSupersededCert = $true }
else { $ignoreSupersededCert = $false }

# check if running in native PoSh ConsoleHost
if ($Host.Name -imatch '^ConsoleHost$') { $psHostConsole = $true }
else { $psHostConsole = $false }

#constants for crypt32.dll methods
[int]$CERT_STORE_PROV_MEMORY = 0x02
[int]$CERT_STORE_PROV_FILE = 0x03
[int]$CERT_STORE_PROV_REG = 0x04
[int]$CERT_STORE_PROV_PKCS7 = 0x05
[int]$CERT_STORE_PROV_SERIALIZED = 0x06
[int]$CERT_STORE_PROV_FILENAME = 0x08
[int]$CERT_STORE_PROV_SYSTEM = 0x0A
[int]$CERT_STORE_PROV_COLLECTION = 0x0B
[int]$CERT_STORE_PROV_SYSTEM_REGISTRY = 0x0D
[int]$CERT_STORE_PROV_SMART_CARD = 0x0F
[int]$CERT_STORE_PROV_LDAP = 0x10

[int]$CERT_STORE_ENUM_ARCHIVED_FLAG = 0x00000200
[int]$CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
[int]$CERT_STORE_READONLY_FLAG = 0x00008000

[int]$CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
[int]$CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
[int]$CERT_SYSTEM_STORE_SERVICES = 0x00050000
[int]$CERT_SYSTEM_STORE_USERS = 0x00060000

#see on input parameters - default to LocalSystem store My (personal computer store), SystemRegistry provider (registry) and LocalSystem storetype
if ($storeName -eq "") { $storeName = "My" }
# system reflect a map (includes Third-Party, Group, Enterprise etc.)
if ($storeProvider -eq "System") { $storeProv = $CERT_STORE_PROV_SYSTEM }
# systemregistry only returns the certificates physically present in the local registry
elseif ($storeProvider -eq "SystemRegistry") { $storeProv = $CERT_STORE_PROV_SYSTEM_REGISTRY }
elseif ($storeProvider -eq "File") { $storeProv = $CERT_STORE_PROV_FILE }
elseif ($storeProvider -eq "LDAP") { $storeProv = $CERT_STORE_PROV_LDAP }
else { $storeProv = $CERT_STORE_PROV_SYSTEM_REGISTRY }
if ($storeType -eq "LocalSystem") { $storeTp = $CERT_SYSTEM_STORE_LOCAL_MACHINE }
elseif ($storeType -eq "CurrentUser") { $storeTp = $CERT_SYSTEM_STORE_CURRENT_USER }
elseif ($storeType -eq "Services") { $storeTp = $CERT_SYSTEM_STORE_SERVICES }
elseif ($storeType -eq "Users") { $storeTp = $CERT_SYSTEM_STORE_USERS }
else { $storeTp = $CERT_SYSTEM_STORE_LOCAL_MACHINE }
#set open_existing and readonly
$storeTp = $storeTp + $CERT_STORE_OPEN_EXISTING_FLAG + $CERT_STORE_READONLY_FLAG


#PoSh 2.0 was shipped with 2008R2/Win7. In order to have as little dependency on later updates
#     as possible this script only uses 2.0 cmdlets
$minimalPSVersion = "2.0"
$CERTVALID = "IsVerified"
$CERTTIMEVALID = "IsTimeValid"

#lookup for certificates snap-in friendly names (in english only)
$storeNameTable = @{"AuthRoot" = "Third-Party Root Certification Authorities";
  "CA"                         = "Intermediate Certification Authorities";
  "Disallowed"                 = "Untrusted Certificates";
  "My"                         = "Personal";
  "REQUEST"                    = "Certificate Enrollment Requests";
  "Root"                       = "Trusted Root Certification Authorities";
  "SmartCardRoot"              = "Smart Card Trusted Roots";
  "Trust"                      = "Enterprise Trust";
  "TrustedDevices"             = "Trusted Devices";
  "TrustedPeople"              = "Trusted People";
  "TrustedPublisher"           = "Trusted Publisher";
  "WebHosting"                 = "Web Hosting"
}

#initialize hash tables
$certificateObjects = @()
$crlObjects = @()
#endregion

#region C# Signature
# C# module imports and types where-type variable
# as CRLs are not implemented in System.Security.Cryptography.X509Certificates
$x509Signature = @"
 using System;
 using System.Runtime.InteropServices;
 using System.Security;
 using System.Security.Cryptography;
 using System.Security.Cryptography.X509Certificates;

 namespace SystemCenterCentral
 {
     namespace Utilities
     {
         namespace Certificates
         {
                 public class X509CRL2
                 {
                     public int Version;
                     public string Type;
                     public X500DistinguishedName IssuerDN;
                     public string Issuer;
                     public DateTime ThisUpdate;
                     public DateTime NextUpdate;
                     public Oid SignatureAlgorithm;
                     public X509ExtensionCollection Extensions;
                     // no need to know every single entry
					 // public X509CRLEntry[] RevokedCertificates;
					 public uint RevokedCertificateCount;

                     //public byte[] RawData;
                 }

				 //no need for CRL entries at the moment
                 //public class X509CRLEntry
                 //{
                 //    public string SerialNumber;
                 //    public DateTime RevocationDate;
                 //    public int ReasonCode;
                 //    public string ReasonMessage;
                 //}

                 public class Helper {
                     [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
                     public static extern int CertCreateCRLContext(
                         int dwCertEncodingType,
                         IntPtr pbCrlEncoded,
                         int cbCrlEncoded
                     );

                     [DllImport("crypt32.dll", EntryPoint="CertEnumCertificatesInStore", CharSet=CharSet.Auto, SetLastError=true)]
                     public static extern IntPtr CertEnumCertificatesInStore(
                                     IntPtr storeProvider,
                                     IntPtr prevCertContext);

                     [DllImport("crypt32.dll", EntryPoint="CertEnumCRLsInStore", CharSet=CharSet.Auto, SetLastError=true)]
                     public static extern IntPtr CertEnumCRLsInStore(
                                    IntPtr storeProvider,
                                     IntPtr prevCrlContext);

                     [DllImport("crypt32.dll", EntryPoint="CertEnumCTLsInStore", CharSet=CharSet.Auto, SetLastError=true)]
                     public static extern IntPtr CertEnumCTLsInStore(
                                    IntPtr storeProvider,
                                     IntPtr prevCtlContext);

                     [DllImport("crypt32.dll", SetLastError = true)]
                     public static extern Boolean CertFreeCRLContext(
                         IntPtr pCrlContext
                     );

                     [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
                     public static extern int CertNameToStr(
                         int dwCertEncodingType,
                         ref CRYPTOAPI_BLOB pName,
                         int dwStrType,
                         System.Text.StringBuilder psz,
                         int csz
                     );

                     [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
                     public static extern IntPtr CertFindExtension(
                         [MarshalAs(UnmanagedType.LPStr)]String pszObjId,
                         int cExtensions,
                         IntPtr rgExtensions
                     );

                     [DllImport("crypt32.dll", EntryPoint="CertOpenStore", CharSet=CharSet.Auto, SetLastError=true)]
                     public static extern IntPtr CertOpenStoreStringPara(
                                     int storeProvider,
                                     int encodingType,
                                     IntPtr hcryptProv,
                                     int flags,
                                     String pvPara);

                     [DllImport("crypt32.dll", EntryPoint="CertCloseStore", CharSet=CharSet.Auto, SetLastError=true)]
                     [return : MarshalAs(UnmanagedType.Bool)]
                     public static extern bool CertCloseStore(
                                     IntPtr storeProvider,
                                     int flags);
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct CRL_CONTEXT
                {
                     public int dwCertEncodingType;
                     // TODO: This should be marshalled right, as BYTE[]
                     // [MarshalAs(UnmanagedType.LPArray, SizeParamIndex=2)]
                     public IntPtr pbCrlEncoded;
                     public uint cbCrlEncoded;
                     // TODO: You can marshal this as CRL_INFO directly
                     public IntPtr pCrlInfo;
                     public IntPtr hCertStore;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
                public struct CRL_INFO
                {
                     public int dwVersion;
                     public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
                     public CRYPTOAPI_BLOB Issuer;
                     public Int64 ThisUpdate;
                     public Int64 NextUpdate;
                     public int cCRLEntry;

                     // TODO: This should be marshalled right, as CRL_ENTRY[] ??
                     public IntPtr rgCRLEntry;
                     public int cExtension;
                     public IntPtr rgExtension;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
                public struct CRYPT_ALGORITHM_IDENTIFIER
                {
                    [MarshalAs(UnmanagedType.LPStr)]public String pszObjId;
                    public CRYPTOAPI_BLOB Parameters;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
                public struct CRYPTOAPI_BLOB
                {
                    public int cbData;
                    public IntPtr pbData;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
                public struct CRL_ENTRY
                {
                    public CRYPTOAPI_BLOB SerialNumber;
                    public Int64 RevocationDate;
                    public int cExtension;
                    public IntPtr rgExtension;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
                public struct CERT_EXTENSION
                {
                    [MarshalAs(UnmanagedType.LPStr)]public String pszObjId;
                    public Boolean fCritical;
                    public CRYPTOAPI_BLOB Value;
                }

             }
     }
 }
"@
#endregion

# Get access to the scripting API
$scomAPI = new-object -comObject "MOM.ScriptAPI"

# check if Powershell >= 2.0 is running
if ( ($PSVersionTable.PSCompatibleVersions) -contains $minimalPSVersion) {
  Write-Host Powershell installed: ( $PSVersionTable.PSVersion.ToString() )
  Write-Host      It is compatible with version $minimalPSVersion required by this script
} else {
  Write-Host Powershell installed: $PSVersionTable.PSVersion.ToString() `t`t`t`t`t`t`t`t -BackgroundColor red
  Write-Host `tIt is not compatible with version $minimalPSVersion required by this script `t -BackgroundColor red
  exit
}


#region check if the flag parameters are valid
$X509ParamValid = $true
$X509ParamEx = ""
try { [System.Security.Cryptography.X509Certificates.X509RevocationFlag]$X509RevocationFlag = $revocationFlag }
catch {
  Write-Warning $_
		$X509ParamValid = $false
		$X509ParamEx += [string]$_ + "
"
		# stick to default
		[System.Security.Cryptography.X509Certificates.X509RevocationFlag]$X509RevocationFlag = "EntireChain"
}
try { [System.Security.Cryptography.X509Certificates.X509RevocationMode]$X509RevocationMode = $revocationMode }
catch {
  Write-Warning $_
		$X509ParamValid = $false
		$X509ParamEx += [string]$_ + "
"
		# stick to default
		[System.Security.Cryptography.X509Certificates.X509RevocationMode]$X509RevocationMode = "NoCheck"
}
try { [System.Security.Cryptography.X509Certificates.X509VerificationFlags]$X509VerificationFlags = $verificationFlags }
catch {
  Write-Warning $_
		$X509ParamValid = $false
		$X509ParamEx += [string]$_ + "
"
		#stick to default
		[System.Security.Cryptography.X509Certificates.X509VerificationFlags]$X509VerificationFlags = "IgnoreCertificateAuthorityRevocationUnknown,IgnoreEndRevocationUnknown"
}
if ($X509ParamValid) {
  $scomAPI.LogScriptEvent($scriptName, 110, 4, "Script starting certificate and CRL discovery/verification:

      Parameters:
      -----------
    storeName: " + $storeName + "
    storeProvider: " + $storeProvider + "
    storeType: " + $storeType + "
    revocationFlag: " + $revocationFlag + "
    revocationMode: " + $revocationMode + "
    verificationFlags: " + $verificationFlags + "
    expiryThresholdDays: " + $expiryThresholdDays + "
    ignoreSupersededCert: " + $ignoreSupersededCert + "
    debugParam: " + $debugParam + "

      PowerShell Host / Version / PID:
      --------------------------------
  " + $host.name + " / " + $PSVersionTable.PSVersion + " / " + $PID)
} else {
  $scomAPI.LogScriptEvent($scriptName, 111, 2, "Script starting with default certificate verification flags as the overridden parameters were invalid:

      Parameters:
      -----------
    storeName: " + $storeName + "
    storeProvider: " + $storeProvider + "
    storeType: " + $storeType + "
    revocationFlag: " + $revocationFlag + "
    revocationMode: " + $revocationMode + "
    verificationFlags: " + $verificationFlags + "
    expiryThresholdDays: " + $expiryThresholdDays + "
    ignoreSupersededCert: " + $ignoreSupersededCert + "
    debugParam: " + $debugParam + "

      PowerShell Host / Version / PID:
      --------------------------------
    " + $host.name + " / " + $PSVersionTable.PSVersion + " / " + $PID + "

      Exception Detail:
      ----------------
  " + $X509ParamEx)
}
#endregion

function main {
  # loading crypt32.dll type to [SystemCenterCentral.Utilities.Certificates.Helper]
  # NOTE: no exception occurs if type was already loaded. Runtime will then just use the previous one
  try
  { Add-Type -TypeDefinition $x509Signature }
  catch {
    #throw "Unable to load [SystemCenterCentral.Utilities.Certificates.X509CRL] and [SystemCenterCentral.Utilities.Certificates.Helper] namespace with crypt32.dll methods"
    $scomAPI.LogScriptEvent($scriptName, 119, 2, "Unable to load [SystemCenterCentral.Utilities.Certificates.X509CRL] and [SystemCenterCentral.Utilities.Certificates.Helper] namespace with crypt32.dll methods. Retrying on the next script run.")
    #exit
		}

  #ready to rumble

  #get certificate store
  $certStorePt = [SystemCenterCentral.Utilities.Certificates.Helper]::CertOpenStoreStringPara($storeProv, 0, 0, $storeTp, $storeName)
  if ($certStorePt -ne 0) {
    # first see about certificates
    #take it from store pointer to full .NET as certificates are exposed there and easier to handle.
    #    this works perfectly for File, LDAP or WinNT service stores.
    $certStore = [System.Security.Cryptography.X509Certificates.X509Store]$certStorePt
    $certificateObjects += @(Get-CertificateProperties -store $certStore -revocationFlag $revocationFlag -revocationMode $revocationMode -verificationFlags $verificationFlags -subjectInclude $subjectIncludeRegEx -issuerInclude $issuerIncludeRegEx -subjectExclude $subjectExcludeRegEx -issuerExclude $issuerExcludeRegEx -enhKeyUseInclude $enhKeyUseIncludeRegEx -enhKeyUseExclude $enhKeyUseExcludeRegEx -templateInclude $templateIncludeRegEx -templateExclude $templateExcludeRegEx -ignoreSuperseded $ignoreSupersededCert)
    if ($certificateObjects.Count -gt 0) { Write-CertificatePropertyBags -certificateObjects $certificateObjects }

    # now proceed with CRLs - this requires crypt32.dll P/Invoke
    $crlPt = [SystemCenterCentral.Utilities.Certificates.Helper]::CertEnumCRLsInStore($certStorePt, 0)
    While ($crlPt -ne 0) {
      $crlObjects += @(Get-X509CRL2 -context $crlPt)
      $crlPt = [SystemCenterCentral.Utilities.Certificates.Helper]::CertEnumCRLsInStore($certStorePt, $crlPt)
    }
    if ($crlObjects.Count -gt 0) { Write-CRLPropertyBags -crlObjects $crlObjects -issuerInclude $issuerIncludeRegEx -issuerExclude $issuerExcludeRegEx }
    # close store
    $closeStore = [SystemCenterCentral.Utilities.Certificates.Helper]::CertCloseStore($certStorePt, 0)
		} else {
    $scomAPI.LogScriptEvent($scriptName, 113, 2, ("Failed to open certificate store.`n`nstoreName: {0}`nstoreProvider: {1}`nstoreType: {2}" -f $storeName, $storeProvider, $storeType))
		}

  #return an empty bag if no objects were found
  if (($certificateObjects.Count -lt 1) -and ($script:crlObjectsReturned -lt 1)) {
    $objVoidBag = $scomAPI.CreatePropertyBag()
    #when running outside native SCOM host, use AddItem as in legacy days to have console output
    if ($psHostConsole -eq $true) { $scomAPI.AddItem($objVoidBag) }
    else { $objVoidBag }
		}
  #when running from command line forcing the return (legacy)
  if ($psHostConsole -eq $true) { $scomAPI.ReturnItems() }


  #write summary event
  $scomAPI.LogScriptEvent($scriptName, 112, 4, ("Script enumerated certificates and CLRs from store '{0}\{1}\{2}'`n`nN° of certs: {3} of {4}`nN° of CRLs: {5} of {6}`n`nThe property bags of this script are being consumed by discovery as well as monitoring workflows.`n`nFilters applied:`nsubject match {7} and notmatch {8}`nissuer match {9} and notmatch {10}`ntemplate match {11} and notmatch {12}`nenhanced key usage OIDs match {13}`nenhanced key usage OIDs notmatch {14}`nUser Context: {15}" -f $storeType, $storeProvider, $storeName, [int]($certificateObjects.Count), [int]($certStore.Certificates.Count), [int]($script:crlObjectsReturned), [int]($crlObjects.Count), [string]$subjectIncludeRegEx, [string]$subjectExcludeRegEx, [string]$issuerIncludeRegEx, [string]$issuerExcludeRegEx, [string]$templateIncludeRegEx, [string]$templateExcludeRegEx, [string]$enhKeyUseIncludeRegEx, [string]$enhKeyUseExcludeRegEx, [string]$userName))
}


function Validate-X509Certificate2
{ # using pure .NET for certificate validation
  param($X509Certificate2, $X509RevocationFlag, $X509RevocationMode, $X509VerificationFlags)

  $X509Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain

  #	EndCertificateOnly: Only the end certificate is checked for revocation.
 	#	EntireChain:		The entire chain of certificates is checked for revocation.
 	#	ExcludeRoot:		The entire chain, except the root certificate, is checked for revocation.
  $X509Chain.ChainPolicy.RevocationFlag = $X509RevocationFlag

  #	NoCheck:	No revocation check is performed on the certificate.
 	#	Offline:	A revocation check is made using a cached certificate revocation list (CRL).
 	#	Online: 	A revocation check is made using an online certificate revocation list (CRL).
  $X509Chain.ChainPolicy.RevocationMode = $X509RevocationMode

  #	AllFlags:										All flags pertaining to verification are included.
 	#	AllowUnknownCertificateAuthority:				Ignore that the chain cannot be verified due to an unknown certificate authority (CA).
 	#	IgnoreCertificateAuthorityRevocationUnknown:	Ignore that the certificate authority revocation is unknown when determining certificate verification.
 	#	IgnoreCtlNotTimeValid:							Ignore that the certificate trust list (CTL) is not valid, for reasons such as the CTL has expired, when determining certificate verification.
 	#	IgnoreCtlSignerRevocationUnknown:				Ignore that the certificate trust list (CTL) signer revocation is unknown when determining certificate verification.
 	#	IgnoreEndRevocationUnknown:						Ignore that the end certificate (the user certificate) revocation is unknown when determining certificate verification.
 	#	IgnoreInvalidBasicConstraints:					Ignore that the basic constraints are not valid when determining certificate verification.
 	#	IgnoreInvalidName:								Ignore that the certificate has an invalid name when determining certificate verification.
 	#	IgnoreInvalidPolicy:							Ignore that the certificate has invalid policy when determining certificate verification.
 	#	IgnoreNotTimeNested:							Ignore that the CA (certificate authority) certificate and the issued certificate have validity periods that are not nested when verifying the certificate. For example, the CA cert can be valid from January 1 to December 1 and the issued certificate from January 2 to December 2, which would mean the validity periods are not nested.
 	#	IgnoreNotTimeValid:								Ignore certificates in the chain that are not valid either because they have expired or they are not yet in effect when determining certificate validity.
 	#	IgnoreRootRevocationUnknown:					Ignore that the root revocation is unknown when determining certificate verification.
 	#	IgnoreWrongUsage:								Ignore that the certificate was not issued for the current use when determining certificate verification.
 	#	NoFlag:											No flags pertaining to verification are included.
  $X509Chain.ChainPolicy.VerificationFlags = $X509VerificationFlags

  #explicitly forcing verificationtime to NOW
  $X509Chain.ChainPolicy.VerificationTime = (Get-Date).ToUniversalTime()


  #Builds an X.509 chain using the policy specified
  #   true if the X.509 certificate is valid; otherwise, false

  if ($X509Chain.Build($X509Certificate2)) {
    $valid = $true
    $statusSummary = $null
    $statusSummaryCert = $null
    $statusSummaryChain = $null
		} else {
    $valid = $false
    $statusSummaryChain = @()
    $statusSummary = $X509Chain.ChainStatus | % {
      if ($_.StatusInformation.ToString().Trim() -imatch '^unknown error\.') { ($_.Status.ToString().Trim() + ":" + "`n") }
      else { ($_.Status.ToString().Trim() + ": " + $_.StatusInformation.ToString().Trim() + "`n") }
    }
    if ($X509Chain.ChainElements.Count -gt 1) {
      #build verbose string with the chain level status
      $chainLevel = ($X509Chain.ChainElements.Count - 1)
      $X509Chain.ChainElements | % {
        #certificate's status
        if ($_.Certificate.Thumbprint -eq $X509Certificate2.Thumbprint) {
          if ($_.ChainElementStatus)	{
            $statusSummaryCert = $_.ChainElementStatus | % {
              if ($_.StatusInformation.ToString().Trim() -imatch '^unknown error\.') { ($_.Status.ToString().Trim() + ":" + "`n") }
              else { ($_.Status.ToString().Trim() + ": " + $_.StatusInformation.ToString().Trim() + "`n") }
            }
          } else {
            $statusSummaryCert = $CERTVALID
          }
        }
        #chain element status
        else {
          $statusSummaryChainObj = New-Object psobject
          $statusSummaryChainObj | Add-Member -MemberType NoteProperty -Name chainLevel -Value $chainLevel
          $statusSummaryChainObj | Add-Member -MemberType NoteProperty -Name chainSubject -Value $_.Certificate.Subject
          if ($_.ChainElementStatus)	{
            $statusSummaryChainCert = $_.ChainElementStatus | % {
              if ($_.StatusInformation.ToString().Trim() -imatch '^unknown error\.') { ($_.Status.ToString().Trim() + ":" + "`n") }
              else { ($_.Status.ToString().Trim() + ": " + $_.StatusInformation.ToString().Trim() + "`n") }
            }
          } else {
            $statusSummaryChainCert = $CERTVALID
          }
          $statusSummaryChainObj | Add-Member -MemberType NoteProperty -Name chainSummary -Value $statusSummaryChainCert

          $statusSummaryChain += $statusSummaryChainObj

        }
        $chainLevel--
      }
    } else {
      $statusSummaryCert = $statusSummary
      $statusSummaryChain = $null
    }
		}
  return $valid, $statusSummary, $statusSummaryCert, $statusSummaryChain
}

function Get-CertificateProperties
{ # call validate and aggregate certificate information with CA version, template name
  param ($store,
    $revocationFlag = "EntireChain",
    $revocationMode = "Online",
    $verificationFlags = "NoFlag",
    $subjectInclude = "^.*$",
    $issuerInclude = "^.*$",
    $subjectExclude = "^$",
    $issuerExclude = "^$",
    $enhKeyUseInclude = "^(|.+)$",
    $enhKeyUseExclude = "^$",
    $templateInclude = "^(|.+)$",
    $templateExclude = "\n",
    $ignoreSuperseded = $true)

  #$certificateList = $null
  $certificateList = @()

  #get and validate all certificates found in the store - except archived ones,
  # certs that match the subject and issuer filters
  # and certificates to be excluded via Enhanced Key Usage (2.5.29.37)
  $store.Certificates | where { $_.Archived -eq $false } | % { `
      $certExluded = $false
    #for certificates with an empty subject. Use 1st SAN line.
    if ($_.Subject.length -eq 0) {
      if ($_.Extensions | where { $_.OID.Value -eq "2.5.29.17" }) {
        $_.Extensions | where { $_.OID.Value -eq "2.5.29.17" } | % {
          $subjectChecked = (($_.Format($true)).Split("`n")[0]).Trim()
        }
      } else { $subjectChecked = "" }
    } else { $subjectChecked = $_.Subject }

    #filter on subject and issuer
    if (($subjectChecked -inotmatch $subjectInclude) -or ($subjectChecked -imatch $subjectExclude))	{ $certExluded = $true }
    if (($_.Issuer -inotmatch $issuerInclude) -or ($_.Issuer -imatch $issuerExclude)) {	$certExluded = $true }
    #filter on enhanced key usage
    if ($_.Extensions | where { $_.OID.Value -eq "2.5.29.37" }) {
      $_.Extensions | where { $_.OID.Value -eq "2.5.29.37" } | % {
        if ($_.EnhancedKeyUsages.Value -join ", " | where { (($_ -notmatch $enhKeyUseInclude) -or ($_ -match $enhKeyUseExclude)) })	{
          $certExluded = $true
        }
      }
    }
    #get certificate template name (if avaliable)
    $templateName = ""
    if ($_.Extensions | where { $_.OID.Value -match "^1\.3\.6\.1\.4\.1\.311\.2(0\.2|1\.7)$" }) {

      #TemplateName (Version 1)
      $_.Extensions | where { $_.OID.Value -match "^1\.3\.6\.1\.4\.1\.311\.20\.2$" } | % {
        $templateName = $_.Format($false).trim()
      }
      #Template (Version 2)
      $_.Extensions | where { $_.OID.Value -match "^1\.3\.6\.1\.4\.1\.311\.21\.7$" } | % {
        #sometimes no actual name but only the OID is contained - if cert is found outside of issuing forest
        # W2K3 systems may have localized output: matching on word characters instead
        #($_.Format($false)) -match 'Template=((?<templateName>.+)\((?<templateOID>1\.3\.6\.1\.4\.1\.311\.[0-9.]+)\)|(?<templateOID>1\.3\.6\.1\.4\.1\.311\.[0-9.]+))' | Out-Null
        ($_.Format($false)) -match '\b\w+\s*=\s*((?<templateName>.+)\((?<templateOID>1\.3\.6\.1\.4\.1\.311\.[0-9.]+)\)|(?<templateOID>1\.3\.6\.1\.4\.1\.311\.[0-9.]+))' | Out-Null
        if ($matches.templateName) { $templateName = ($matches.templateName.trim() + "(" + $matches.templateOID.trim() + ")") }
        else { $templateName = $matches.templateOID.trim() }
      }
    }
    #filter on template name (might be OID)
    if (($templateName -inotmatch $templateInclude) -or ($templateName -imatch $templateExclude))	{ $certExluded = $true }

    #get SANs as a list
    $SANs = ""
    $SANList = @()
    if ($_.Extensions | where { $_.OID.Value -eq "2.5.29.17" }) {
      $_.Extensions | where { $_.OID.Value -eq "2.5.29.17" } | % {
        $SANList += (($_.Format($true).Trim() -split "\n"))
      }
    }
    $SANs = ($SANList | Sort-Object ) -join ", "

    #get certificate Enhanced Key Usage List (if avaliable)
    $EKU = "<null>: all purpose certificate"
    $EKUList = @()
    if ($_.EnhancedKeyUsageList.Count -gt 0) {
      $_.EnhancedKeyUsageList | Sort-Object ObjectId | ForEach-Object {
        if ($_.FriendlyName) {
          $EKUList += """{0}: {1}""" -f $_.FriendlyName, $_.ObjectId
        } else {
          $EKUList += $_.ObjectId
        }
      }
      $EKU = $EKUList -join ", "
    }

    if ($certExluded -eq $false) {
      # get service properties from various sources
      $caVersionByte = 0
      $certificateObj = New-Object psobject
      $certificateObj | Add-Member -MemberType NoteProperty -Name certSubjectChk -Value $subjectChecked
      $certificateObj | Add-Member -MemberType NoteProperty -Name cert -Value $_

      # checking "EntireChain", "Online" and not using any tolerate flags "NoFlag"
      #   that's as picky as one can get
      $validCert = Validate-X509Certificate2 -X509Certificate2 $_ -X509RevocationFlag $X509RevocationFlag -X509RevocationMode $X509RevocationMode -X509VerificationFlags $X509VerificationFlags

      $certificateObj | Add-Member -MemberType NoteProperty -Name certValid -Value $validCert[0]
      $certificateObj | Add-Member -MemberType NoteProperty -Name certValidationString -Value $validCert[1]
      $certificateObj | Add-Member -MemberType NoteProperty -Name certValidationCertificateString -Value $validCert[2]
      #convert chain validation object into a string
      $certificateObj | Add-Member -MemberType NoteProperty -Name certValidationChainString -Value $validCert[3]

      # check if the szOID_CERTSRV_CA_VERSION - 1.3.6.1.4.1.311.21.1 extension is used
      #   and learn the CA version
      #   CA certificates will return either version number (e.g. 2.0) or "n/a" if
      #         no version number extension was found
      #   normal certs will have an empty string ""
      if ($_.Extensions | where { $_.OID.Value -eq "2.5.29.19" }) {
        if ($_.Extensions | where { $_.OID.Value -eq "1.3.6.1.4.1.311.21.1" }) {
          # ASN.1 decoded format of CAVersion will return V1.0 or similar
          $caVersion = [double]((($_.Extensions | where { $_.OID.Value -eq "1.3.6.1.4.1.311.21.1" }).Format($false)).Replace('V', ''))
        } else { $caVersion = "n/a" }
      } else { $caVersion = "" }

      $certificateObj | Add-Member -MemberType NoteProperty -Name certCAVersion -Value $caVersion

      $certificateObj | Add-Member -MemberType NoteProperty -Name certTemplate -Value $templateName
      $certificateObj | Add-Member -MemberType NoteProperty -Name certEKU -Value $EKU
      $certificateObj | Add-Member -MemberType NoteProperty -Name certSAN -Value $SANs
      $certificateList += @($certificateObj)
    }
  }
  #filter certificateList to only the latest (valid the longest) certificate of one breed
  #    subject, SANs, issuers, EKUs and template are considered grouping properties
  if ($ignoreSuperseded -eq $true) {
    $certificateList = @(
      $certificateList | Group-Object certSubjectChk, certSAN, cert.IssuerName.Name, certEKU, certTemplate | ForEach-Object {
        $_.Group | Sort-Object { [System.DateTime]$_.cert.NotAfter } -Descending | Select-Object -First 1 }
    )
  }
  return $certificateList
}

function Write-CertificatePropertyBags {
  param ($certificateObjects)

  #evaluate the highest CAVersion number
  $versionedCACertHigh = @{ }
  $certificateObjects | where { ($_.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') -and ($_.certCAVersion -ne 'n/a') -and ($_.certCAVersion -ge 0) } | % `
  {
    #add instance issues to hash
    if (!$versionedCACertHigh.ContainsKey($_.cert.Issuer)) {
      $versionedCACertHigh.Add($_.cert.Issuer, $_.certCAVersion)
    } else {
      if ([double]($versionedCACertHigh.get_Item($_.cert.Issuer)) -lt [double]$_.certCAVersion) {
        $versionedCACertHigh.set_Item($_.cert.Issuer, $_.certCAVersion)
      }
    }
  }

  #build SCOM propertybag
  $certificateObjects | where { ($_.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') } | % { `

    $certStatusString = ''
    $certStatusIgnoreUntrustedRootString = ''
    $certVerboseStatusString = ''
    $certTimeStatusString = ''
    $certVerboseTimeStatusString = ''
    #build a SCOM property bag
    $objCertBag = $scomAPI.CreatePropertyBag()

    $objCertBag.AddValue("InstanceType", "Certificate")
    $objCertBag.AddValue("UserContext", [string]$userName)
    $objCertBag.AddValue("CertVersion", [string]$_.cert.Version)
    $objCertBag.AddValue("CertSerial", [string]$_.cert.SerialNumber)
    $objCertBag.AddValue("CertSignatureAlgo", [string]$_.cert.SignatureAlgorithm.FriendlyName)
    $objCertBag.AddValue("CertIssuedBy", [string]$_.cert.IssuerName.Name)
    $objCertBag.AddValue("CertValidFrom", [string]$_.cert.NotBefore.ToUniversalTime())
    $objCertBag.AddValue("CertValidTo", [string]$_.cert.NotAfter.ToUniversalTime())
    #if subject is empty this will contain the 1st SAN
    $objCertBag.AddValue("CertIssuedTo", [string]$_.certSubjectChk)
    $objCertBag.AddValue("CertPublicKey", [string]$_.cert.PublicKey.Key.KeyExchangeAlgorithm)
    $objCertBag.AddValue("CertFriendlyName", [string]$_.cert.FriendlyName)
    $objCertBag.AddValue("CertThumbprint", [string]$_.cert.Thumbprint)
    $objCertBag.AddValue("CertSAN", [string]$_.certSAN)

    #see if in extensions "CertificateAuthority" is set
    if ($_.cert.Extensions | where { (($_.OID.Value -eq "2.5.29.19") -and ($_.CertificateAuthority -eq $true)) }) {
      $objCertBag.AddValue("CertIsCertificateAuthority", "True")
      $isCACert = $true
    } Else {
      $objCertBag.AddValue("CertIsCertificateAuthority", "False")
      $isCACert = $false
    }
    #check if self-signed (SubjectName and IssuerName match)
    if ($_.cert.IssuerName.Name -eq $_.cert.SubjectName.Name) { $objCertBag.AddValue("CertIsSelfSigned", "True") }
    else { $objCertBag.AddValue("CertIsSelfSigned", "False") }


    $objCertBag.AddValue("CertPrivateKey", [string]$_.cert.HasPrivateKey)

    $objCertBag.AddValue("CertDaysStillValid", [long]($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).Days)

    #descriptive string used in expiry alert descriptions
    if (((($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays) -ge 0) -and ((($_.cert.NotBefore.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays) -lt 0)) { $lifetimeMessage = " expires in " + [string]($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).Days + " days on " + [string]$_.cert.NotAfter.ToUniversalTime() + " UTC" }
    if ((($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays) -lt 0) { $lifetimeMessage = " has expired on " + [string]$_.cert.NotAfter.ToUniversalTime() + " UTC" }
    if ((($_.cert.NotBefore.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays) -ge 0) { $lifetimeMessage = " is not valid until on or after " + [string]$_.cert.NotBefore.ToUniversalTime() + " UTC" }
    # CtlNotTimeValid and NotTimeNested on certificate
    if ($_.certValidationCertificateString -match "CtlNotTimeValid:") { $lifetimeMessage = "'s chain is not in a valid time range. Check if intermediate or root certificates have to be renewed" }
    if ($_.certValidationCertificateString -match "NotTimeNested:") { $lifetimeMessage = " and the CA (certificate authority) certificate have validity periods that are not nested. For example, the CA cert can be valid from January 1 to December 1 and the issued certificate from January 2 to December 2, which would mean the validity periods are not nested" }
    #check a rare case when not the certificate but the chain's lifetime has expired or it isn't nested
    # using new "certValidationChainString" in V5
    if ($_.certValidationChainString ) {
      $_.certValidationChainString | % {
        if ($_.chainSummary -imatch "(NotTimeValid|CtlNotTimeValid):") {
          $lifetimeMessage = "'s chain is not in a valid time range. Check if intermediate or root certificates have to be renewed"
          if ($_.chainSummary -match "NotTimeNested:") { $lifetimeMessage = "'s chain certificates have validity periods that are not nested. For example, the intermediate CA cert can be valid from January 1 to December 1 and the root CA cert from January 2 to December 2, which would mean the validity periods are not nested" }
        }
      }
    }
    $objCertBag.AddValue("CertLifeTimeMessage", $lifetimeMessage)

    #static flag set to true if the certificate expires in less than a month.
    #   changed to dynamic value via parameter
    #if (([long](($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).Days) -le 31) -and ([long](($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).Days) -ge 0)) {$objCertBag.AddValue("CertExpiresWithin31Days", "true")}
    if (([long](($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).Days) -le $expiryThresholdDays) -and ([long](($_.cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).Days) -ge 0)) {
      $objCertBag.AddValue("CertExpiresSoon", "true")
      $certExpiresSoon = "true"
    } else {
      $objCertBag.AddValue("CertExpiresSoon", "false")
      $certExpiresSoon = "false"
    }

    #descriptive string informing why the validation failed
    #   filter 'NotTimeValid:' as this is being taken care of by the time properties
    #despite setting the revocation flags, chain build still seems to return "RevocationStatusUnknown" and "OfflineRevocation"
    #   treat these as valid
    #filtering status 'UntrustedRoot' as an option for self-signed certificates in personal stores
    #     caveat: it would still show as an error in certmgr GUI...
    $validationStatusMatch = '^(NotTimeValid:|CtlNotTimeValid:|NotTimeNested:|RevocationStatusUnknown:|OfflineRevocation:)'
    $validationStatusMatchIgnoreUntrustedRoot = '^(NotTimeValid:|CtlNotTimeValid:|NotTimeNested:|RevocationStatusUnknown:|OfflineRevocation:|UntrustedRoot:)'
    $validationTimeStatusMatch = '^(NotTimeValid:|CtlNotTimeValid:|NotTimeNested:)'
    if ($_.certValidationString -ne $null) {
      $certStatusString = [string]($_.certValidationString | where { $_ -notmatch $validationStatusMatch } | % { (($_).trim() + " ### ") })
      $certStatusIgnoreUntrustedRootString = [string]($_.certValidationString | where { $_ -notmatch $validationStatusMatchIgnoreUntrustedRoot } | % { (($_).trim() + " ### ") })
      $certTimeStatusString = [string]($_.certValidationString | where { $_ -match $validationTimeStatusMatch } | % { (($_).trim() + " ### ") })
    }

    #more verbose output taking into account the chain's status
    if ($_.certValidationString -ne $null) {
      #check summary for time issue
      $certVerboseStatusString = [string]($_.certValidationString | where { $_ -notmatch $validationStatusMatch } | % { (($_).trim()) })
      if ($certVerboseStatusString.length -gt 0) {
        #get certificate issue
        $certVerboseStatusString = [string]($_.certValidationCertificateString | where { $_ -notmatch $validationStatusMatch } | % { (($_).trim() + "`n") })
        if ($certVerboseStatusString.length -le 0) { $certVerboseStatusString = $CERTVALID + "`n" }
        $certVerboseStatusString = "--- Certificate Status ---`n" + $certVerboseStatusString
        if ($_.certValidationChainString -ne $null ) {
          $certVerboseStatusString = $certVerboseStatusString + "`n--- Chain Status Overview ---`n"
          $_.certValidationChainString | % {
            $certVerboseStatusStringChain = ($_.chainSummary | where { $_ -notmatch $validationStatusMatch })
            if ($certVerboseStatusStringChain.length -le 0) { $certVerboseStatusStringChain = $CERTVALID + "`n" }
            $certVerboseStatusString = $certVerboseStatusString + ("Level " + $_.ChainLevel + ": " + $_.ChainSubject + "`n" + $certVerboseStatusStringChain + "`n") }
        }
      }



      #check summary for time issue
      $certVerboseTimeStatusString = [string]($_.certValidationString | where { $_ -match $validationTimeStatusMatch } | % { (($_).trim()) })
      if ($certVerboseTimeStatusString.length -gt 0) {
        #get certificate issue from
        $certVerboseTimeStatusString = [string]($_.certValidationCertificateString | where { $_ -match $validationTimeStatusMatch } | % { (($_).trim() + "`n") })
        if ($certVerboseTimeStatusString.length -le 0) { $certVerboseTimeStatusString = $CERTVALID + "`n" }
        $certVerboseTimeStatusString = "--- Certificate Status ---`n" + $certVerboseTimeStatusString
        if ($_.certValidationChainString -ne $null ) {
          $certVerboseTimeStatusString = $certVerboseTimeStatusString + "`n--- Chain Status Overview ---`n"
          $_.certValidationChainString | % {
            $certVerboseTimeStatusStringChain = ($_.chainSummary | where { $_ -match $validationTimeStatusMatch })
            if ($certVerboseTimeStatusStringChain.length -le 0) { $certVerboseTimeStatusStringChain = $CERTVALID + "`n" }
            $certVerboseTimeStatusString = $certVerboseTimeStatusString + ("Level " + $_.ChainLevel + ":" + $_.ChainSubject + "`n" + $certVerboseTimeStatusStringChain + "`n")
          }
        }
      }
    }

    #set valid strings respectively clean ending separator
    if (($certStatusString -eq $null) -or ($certStatusString -eq '')) { $certStatusString = $CERTVALID }
    else { $certStatusString = ($certStatusString.Substring(0, $certStatusString.length - 5)).trim() }
    if (($certStatusIgnoreUntrustedRootString -eq $null) -or ($certStatusIgnoreUntrustedRootString -eq '')) { $certStatusIgnoreUntrustedRootString = $CERTVALID }
    else { $certStatusIgnoreUntrustedRootString = ($certStatusIgnoreUntrustedRootString.Substring(0, $certStatusIgnoreUntrustedRootString.length - 5)).trim() }
    if (($certTimeStatusString -eq $null) -or ($certTimeStatusString -eq '')) { $certTimeStatusString = $CERTTIMEVALID }
    else { $certTimeStatusString = ($certTimeStatusString.Substring(0, $certTimeStatusString.length - 5)).trim() }

    $objCertBag.AddValue("CertStatus", $certStatusString)
    $objCertBag.AddValue("CertStatusIgnoreUntrustedRoot", $certStatusIgnoreUntrustedRootString)
    $objCertBag.AddValue("CertTimeStatus", $certTimeStatusString)
    $objCertBag.AddValue("CertVerboseStatus", $certVerboseStatusString)
    $objCertBag.AddValue("CertVerboseTimeStatus", $certVerboseTimeStatusString)

    #  szOID_CERTSRV_CA_VERSION - 1.3.6.1.4.1.311.21.1
    #     flag all but the most recent CA certificate as replaced
    if (($_.certCAVersion -ne 'n/a') -and ($_.certCAVersion -ge 0)) {
      #if superseded then flag
      if ($_.certCAVersion -ne ($versionedCACertHigh.get_Item($_.cert.Issuer))) {
        # set version string so that discovery can filter
        $certCAVersionString = ([string]$_.certCAVersion + " (superseded)")
      } else { $certCAVersionString = ([string]$_.certCAVersion + " (current)") }
    } else { $certCAVersionString = ([string]$_.certCAVersion) }
    $objCertBag.AddValue("CAVersion", $certCAVersionString)

    # rely on $Data[Default='n/a']/Property[@Name='TemplateName']$ during discovery mapper to set a valid default
    if (([string]$_.certTemplate).length -gt 0) {
      $objCertBag.AddValue("TemplateName", [string]$_.certTemplate)
    }

    $objCertBag.AddValue("EnhancedKeyUsageList", $_.certEKU)

    if ($debugScript) {
      $certOutput = "
        CERTIFICATE
        -----------
      CertIssuedTo: " + [string]$_.certSubjectChk + "
      CertIssuedBy: " + [string]$_.cert.IssuerName.Name + "
      SANs: " + [string]$_.certSAN + "
      TemplateName: " + [string]$_.certTemplate + "
      EKUs: " + [string]$_.certEKU + "

      CertValidFrom (UTC): " + [string]$_.cert.NotBefore.ToUniversalTime() + "
      CertValidTo (UTC): " + [string]$_.cert.NotAfter.ToUniversalTime() + "

      CertVersion: " + [string]$_.cert.Version + "
      CertSerial: " + [string]$_.cert.SerialNumber + "
      CertSignatureAlgo: " + [string]$_.cert.SignatureAlgorithm.FriendlyName + "
      CertPublicKey: " + [string]$_.cert.PublicKey.Key.KeyExchangeAlgorithm + "
      CertFriendlyName: " + [string]$_.cert.FriendlyName + "
      CertThumbprint: " + [string]$_.cert.Thumbprint + "
      CertPrivateKey: " + [string]$_.cert.HasPrivateKey + "

      CertIsCertificateAuthority: " + $isCACert + "
      CertIsSelfSigned: " + ($_.cert.IssuerName.Name -eq $_.cert.SubjectName.Name) + "

      CAVersion: " + $certCAVersionString + "

      CertExpiresSoon (views/reports): " + $certExpiresSoon + "

      CertStatusString: " + $certStatusString + "
      CertStatusIgnoreUntrustedRoot " + $certStatusIgnoreUntrustedRootString + "
      CertTimeStatus: " + $certTimeStatusString + "
      CertLifeTimeMessage: " + $lifetimeMessage


      $scomAPI.LogScriptEvent($scriptName, 114, 4, "DEBUG: Adding certificate..." + $certOutput)
    }
    #when running outside native SCOM host, use AddItem as in legacy days to have console output
    if ($psHostConsole -eq $true) { $scomAPI.AddItem($objCertBag) }
    else { $objCertBag }
  }


}

function Write-CRLPropertyBags {
  #only return the latest CRL(s) with the highest caVersion extension
  param ($crlObjects, [string]$issuerInclude = "^.*$", [string]$issuerExclude = "^$")

  #get additional properties from extensions - especially CA Version
  $versionedCRLHigh = @{ }
  $crlList = @()
  $pbgdCRLs = 0
  $crlObjects | % { `
      #skip CRLs that match the issuer filter
      if (($_.Issuer -imatch $issuerInclude) -and ($_.Issuer -inotmatch $issuerExclude)) {
      # check if the szOID_CERTSRV_CA_VERSION - 1.3.6.1.4.1.311.21.1 extension is used
      #   and learn the CA version
      if ($_.Extensions | where { $_.OID.Value -eq "1.3.6.1.4.1.311.21.1" }) {
        # ASN.1 decoded format of CAVersion will return V1.0 or similar
        $caVersion = [double]((($_.Extensions | where { $_.OID.Value -eq "1.3.6.1.4.1.311.21.1" }).Format($false)).Replace('V', ''))
      } else { $caVersion = "n/a" }

      # Authority Key Identier
      if ($_.Extensions | where { $_.OID.Value -eq "2.5.29.35" }) {
        # ASN.1 decoded format of Authority Key Identifier
        $authKeyId = (($_.Extensions | where { $_.OID.Value -eq "2.5.29.35" }).Format($false)).Replace('KeyID=', '')
      } else { $authKeyId = "" }

      # CRL Number
      if ($_.Extensions | where { $_.OID.Value -eq "2.5.29.20" }) {
        # ASN.1 decoded format of Authority Key Identifier
        $crlNumber = ($_.Extensions | where { $_.OID.Value -eq "2.5.29.20" }).Format($false)
      } else { $crlNumber = "" }

      #evaluate the highest CAVersion number
      if (($caVersion -ne 'n/a') -and ($caVersion -ge 0)) {
        #add instance issues to hash
        if (!$versionedCRLHigh.ContainsKey($_.Issuer))	{ $versionedCRLHigh.Add($_.Issuer, $caVersion) }
        else {
          if (($versionedCRLHigh.get_Item($_.Issuer)) -lt $caVersion) { $versionedCRLHigh.set_Item($_.Issuer, $caVersion)	}
        }
      }

      #now add all the additional properties to an object
      $crlObjEnh = New-Object psobject
      $crlObjEnh | Add-Member -MemberType NoteProperty -Name crl -Value $_
      $crlObjEnh | Add-Member -MemberType NoteProperty -Name caVersion -Value $caVersion
      $crlObjEnh | Add-Member -MemberType NoteProperty -Name authKeyId -Value $authKeyId
      $crlObjEnh | Add-Member -MemberType NoteProperty -Name crlNumber -Value $crlNumber

      $crlList += @($crlObjEnh)
    }
		}

  $crlList | % { `

    ##skip all but the most recent caVersion CRL
    if (($_.caVersion -eq 'n/a') -or ($_.caVersion -eq ($versionedCRLHigh.get_Item($_.crl.Issuer)))) {
      #build a SCOM property bag
      $objCRLBag = $scomAPI.CreatePropertyBag()

      $objCRLBag.AddValue("InstanceType", "CRL")
      $objCRLBag.AddValue("UserContext", [string]$userName)
      $objCRLBag.AddValue("CRLVersion", [string]$_.crl.Version)
      $objCRLBag.AddValue("CRLSigAlg", [string]$_.crl.SignatureAlgorithm.FriendlyName)
      $objCRLBag.AddValue("CRLIssuedBy", [string]$_.crl.Issuer)
      $objCRLBag.AddValue("CRLThisUpdate", [string]$_.crl.ThisUpdate.ToUniversalTime())
      $objCRLBag.AddValue("CRLNextUpdate", [string]$_.crl.NextUpdate.ToUniversalTime())
      $objCRLBag.AddValue("CRLEntries", [int64]$_.crl.RevokedCertificateCount)
      #CERT_SHA1_HASH_PROP_ID is not exposed, hence build a key using various properties instead
      #     as this is used only to provide SCOM object key that's fine
      $objCRLBag.AddValue("CRLHash", [string](Get-SHA1Hash -inputString ($_.crl.Issuer + $_.authKeyId)))

      #properties from extensions
      $objCRLBag.AddValue("CRLCAVersion", [string]$_.caVersion)
      $objCRLBag.AddValue("CRLAuthKeyId", [string]$_.authKeyId)
      $objCRLBag.AddValue("CRLNumber", [string]$_.crlNumber)

      $objCRLBag.AddValue("CRLDaysUntilUpdate", [double](($_.crl.NextUpdate - (Get-Date)).Days))
      if ((($_.crl.NextUpdate - (Get-Date)).TotalDays) -le 0) { $objCRLBag.AddValue("CRLNeedsUpdate", "True") }
      else { $objCRLBag.AddValue("CRLNeedsUpdate", "False") }

      if ($debugScript) {
        $crlOutput = "
CRL
-----------
CRLIssuedBy: " + [string]$_.crl.Issuer + "

CRLThisUpdate (UTC): " + [string]$_.crl.ThisUpdate.ToUniversalTime() + "
CRLNextUpdate (UTC): " + [string]$_.crl.NextUpdate.ToUniversalTime() + "

CRLVersion: " + [string]$_.crl.Version + "
CRLSigAlg: " + [string]$_.crl.SignatureAlgorithm.FriendlyName + "
CRLEntries: " + [int]$_.crl.RevokedCertificateCount + "
CRLHash: " + [string](Get-SHA1Hash -inputString ($_.crl.Issuer + $_.authKeyId)) + "
CRLCAVersion: " + [string]$_.caVersion + "
CRLAuthKeyId: " + [string]$_.authKeyId + "
CRLDaysUntilUpdate: " + [double](($_.crl.NextUpdate - (Get-Date)).Days)

        $scomAPI.LogScriptEvent($scriptName, 115, 4, "DEBUG: ADDING CRL..." + $crlOutput)
      }
      ++$pbgdCRLs
      #when running outside native SCOM host, use AddItem as in legacy days to have console output
      if ($psHostConsole -eq $true) { $scomAPI.AddItem($objCRLBag) }
      else { $objCRLBag }
    } else {
      if ($debugScript) {
        $crlOutput = "
CRL
-----------
CRLIssuedBy: " + [string]$_.crl.Issuer + "

CRLThisUpdate: " + [string]$_.crl.ThisUpdate.ToUniversalTime() + "
CRLNextUpdate: " + [string]$_.crl.NextUpdate.ToUniversalTime() + "

CRLVersion: " + [string]$_.crl.Version + "
CRLSigAlg: " + [string]$_.crl.SignatureAlgorithm.FriendlyName + "
CRLEntries: " + [int]$_.crl.RevokedCertificateCount + "
CRLHash: " + [string](Get-SHA1Hash -inputString ($_.crl.Issuer + $_.authKeyId)) + "
CRLCAVersion: " + [string]$_.caVersion + "
CRLAuthKeyId: " + [string]$_.authKeyId + "
CRLDaysUntilUpdate: " + [double](($_.crl.NextUpdate - (Get-Date)).Days)

        $scomAPI.LogScriptEvent($scriptName, 115, 4, "DEBUG: Skipping this CRL because its CAVersion (" + [string]$_.caVersion + ") is lower than the maximum of " + [string]($versionedCRLHigh.get_Item($_.crl.Issuer)) + $crlOutput)
      }
    }
		}
	 $script:crlObjectsReturned = $pbgdCRLs
}

# enumerating CRLs using P/Invoke on crypt32.dll
function Get-X509CRL2 {
  Param ([IntPtr]$context)

  # This function and the here-string $x509CRL2Namespace are based on a script by
  # Vadims Podāns - vpodans@sysadmins.lv
  # 				http://www.sysadmins.lv/CategoryView,category,PowerShell,6.aspx

  #variables
  [IntPtr]$pByte = [IntPtr]::Zero
  [byte]$bByte = 0
  [IntPtr]$rgExtension = [IntPtr]::Zero
  $ptr = [IntPtr]::Zero

  #prepare empty
  $crl = New-Object SystemCenterCentral.Utilities.Certificates.X509CRL2

  $crlContext = [Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]$context, [Type][SystemCenterCentral.Utilities.Certificates.CRL_CONTEXT])
  $crlInfo = [Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]$crlContext.pCrlInfo, [Type][SystemCenterCentral.Utilities.Certificates.CRL_INFO])

  #fill
  $crl.Version = $crlInfo.dwVersion + 1
  $crl.Type = "Base CRL"
  #no raw data
  #$crl.RawData = $cBytes
  $crl.SignatureAlgorithm = New-Object Security.Cryptography.Oid $crlInfo.SignatureAlgorithm.pszObjId
  $CRL.ThisUpdate = [datetime]::FromFileTime($CRLInfo.ThisUpdate)
  $CRL.NextUpdate = [datetime]::FromFileTime($CRLInfo.NextUpdate)
  $csz = [SystemCenterCentral.Utilities.Certificates.Helper]::CertNameToStr(65537, [ref]$CRLInfo.Issuer, 3, $null, 0)
  $psz = New-Object text.StringBuilder $csz
  $csz = [SystemCenterCentral.Utilities.Certificates.Helper]::CertNameToStr(65537, [ref]$CRLInfo.Issuer, 3, $psz, $csz)
  $CRL.IssuerDN = New-Object Security.Cryptography.X509Certificates.X500DistinguishedName $psz
  $CRL.Issuer = $CRL.IssuerDN.Format(0)

  #knowing just the number of entries is good enough
  $CRL.RevokedCertificateCount = $CRLInfo.cCRLEntry

  $rgExtension = $CRLInfo.rgExtension
  if ($CRLInfo.cExtension -ge 1) {
    $Exts = New-Object Security.Cryptography.X509Certificates.X509ExtensionCollection
    for ($n = 0; $n -lt $CRLInfo.cExtension; $n++) {
      $ExtEntry = [Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]$rgExtension, [Type][SystemCenterCentral.Utilities.Certificates.CERT_EXTENSION])
      [IntPtr]$rgExtension = [SystemCenterCentral.Utilities.Certificates.Helper]::CertFindExtension($ExtEntry.pszObjId, $CRLInfo.cExtension, $CRLInfo.rgExtension)
      $pByte = $ExtEntry.Value.pbData
      $bBytes = $null
      for ($m = 0; $m -lt $ExtEntry.Value.cbData; $m++) {
        [byte[]]$bBytes += [Runtime.InteropServices.Marshal]::ReadByte($pByte)
        ### this does not work on PoSh 2.0
        #$pByte = [InTPtr]::Add($pByte, 1)
        $pByte = [Int64]$pByte + [Runtime.InteropServices.Marshal]::SizeOf([Type][byte])
      }
      $ext = New-Object Security.Cryptography.X509Certificates.X509Extension $ExtEntry.pszObjId, @([Byte[]]$bBytes), $ExtEntry.fCritical
      [void]$Exts.Add($ext)
      ### this does not work on PoSh 2.0
      #$rgExtension = [IntPtr]::Add($rgExtension, ([Runtime.InteropServices.Marshal]::SizeOf([Type][SystemCenterCentral.Utilities.Certificates.CERT_EXTENSION])))
      $rgExtension = [long]$rgExtension + [Runtime.InteropServices.Marshal]::SizeOf([Type][SystemCenterCentral.Utilities.Certificates.CERT_EXTENSION])
    }
    if ($exts | ? { $_.Oid.Value -eq "2.5.29.27" }) { $CRL.Type = "Delta CRL" }
    $CRL.Extensions = $Exts
  }

  return $crl
}


function Get-SHA1Hash {
  Param ([string]$inputString)
  $sha1CryptoServiceProvider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
  return [System.BitConverter]::ToString($sha1CryptoServiceProvider.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString)))
}

#call main function
Main
