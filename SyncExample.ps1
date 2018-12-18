#Import Module
$ScriptDir = split-path -parent $MyInvocation.MyCommand.Definition
Import-Module "$ScriptDir\AdobeUMInterface.psm1"

#Load cert for auth
$SignatureCert = Import-PFXCert -Password "MyPassword" -CertPath "$ScriptDir\Private.pfx"

#Client info from https://console.adobe.io/
$ClientInformation = New-ClientInformation -APIKey "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -OrganizationID "xxxxxxxxxxxxxxxxxxxxxxxx@AdobeOrg" -ClientSecret "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -TechnicalAccountID "xxxxxxxxxxxxxxxxxxxxxxxx@techacct.adobe.com" -TechnicalAccountEmail "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@techacct.adobe.com"

#Required auth token for further adobe queries. (Is placed in ClientInformation)
Get-AdobeAuthToken -ClientInformation $ClientInformation -SignatureCert $SignatureCert

#Sync AD Group to Adobe
#You can get the groupid by running Get-AdobeGroups
$Request = New-SyncADGroupRequest -ADGroupName "My-AD-Group" -AdobeGroupName "11111111" -ClientInformation $ClientInformation

#ToReview, uncomment
#Write-Host ($Request | ConvertTo-JSON -Depth 10)

#Send the generated request to adobe
Send-UserManagementRequest -ClientInformation $ClientInformation -Requests $Request