# AdobeUMInterface

A PowerShell module for communicating with Adobe's User Management API. **Warning**, if you used prior versions of these functions, they are not compatible with recent changes. Most functions have been updated to use the [non-deprecated API functions.](https://Adobe-apiplatform.github.io/umapi-documentation/en/api/DeprecatedApis.html)

## General Request Pattern

Each request sent to Adobe can be split up into 2 parts
1) You have an identity that you are trying to act on. (A user or group for example)
2) You have actions that you want to perform on the identity.

An identity and a list of actions together, make a full request. Keep this in mind when you look at the PowerShell functions.

In general, you can run the New-\*Action functions, add those to an array, then pass them on to the New-\*Request functions. A list of New-\*Request functions can then be sent to Adobe for processing with the Send-UserManagementRequest.
I encourage you to look at the structure of the returns objects from the New-\*Request functions to get a better understanding.

## General Usage Instructions

1) Create a service account/integration and link it to your User Management binding. (Do this at [Adobe's Console](https://console.Adobe.io))
2) Create a signing certificate. You can create a self signed one using the provided New-Cert command
3) Export a public version certificate of your certificate. 
4) Upload the public cert to the integration you created in step 1.
5) Using the information Adobe gave you in step 1, call New-ClientInformation and provide it the necessary information. (APIKey, ClientSecret, etc)
6) Load your certificate in PowerShell. You can do this with the provided Import-AdobeUMCert function.
7) Call Get-AdobeAuthToken, to request an auth token from Adobe, this validates further requests to Adobe.
8) Utilize the other functions, and your ClientInformation variable, to make further queries against your Adobe users and groups.

A complete example of the calls you should make after step 5 is below. The script below, creates an "add to group" action and then passes that to a "Create User" request. Then that request is sent to Adobe for processing.

```PowerShell
#Load the Auth cert generated with New-Cert
#$SignatureCert = Import-AdobeUMCert -Password "MyPassword" -CertPath "C:\Certs\AdobeAuthPrivate.pfx" #from file or
$SignatureCert = Import-AdobeUMCert -CertThumbprint "0000000000000000000000000000000000000000" -CertStore "LocalMachine" #From windows store

#Client info from https://console.Adobe.io/
$ClientInformation = New-ClientInformation -APIKey "1234123412341234" -OrganizationID "1234123412341234@AdobeOrg" -ClientSecret "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx" `
    -TechnicalAccountID "12341234123412341234B@techacct.Adobe.com" -TechnicalAccountEmail "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx6@techacct.Adobe.com"

#Required auth token for further Adobe queries. (Is placed in ClientInformation)
Get-AdobeAuthToken -ClientInformation $ClientInformation -SignatureCert $SignatureCert

#Add a new user, and add them to a group in one Adobe request
$GroupAddAction = New-GroupAddAction -Groups "All Apps Users"
$Request = New-CreateUserRequest -FirstName "John" -LastName "Doe" -Email "John.Doe@domain.com" -AdditionalActions $GroupAddAction

#Send the generated request to Adobe
Send-UserManagementRequest -ClientInformation $ClientInformation -Requests $Request
```

## Sync with an AD Group

For an easier experience, consider using the official [Adobe User Sync Tool](https://helpx.adobe.com/enterprise/using/user-sync.html).

The end-goal I had in mind for these was to automatically sync an AD group with Adobe's portal. This allows easy delegation to a service desk. The group used can also be tied in with AppLocker, and automatic deployments could use the same group in SCCM or another application management utility. The general pattern is:

1) Create an active directory group that your Adobe Users will be added to
2) Create another group Adobe-side
3) Get the Adobe group ID by running Get-AdobeGroups
4) Create a script like below, and assign it to a scheduled task to run periodically

```PowerShell
#Import Module
$ScriptDir = split-path -parent $MyInvocation.MyCommand.Definition
Import-Module "$ScriptDir\AdobeUMInterface.psm1"

#Load cert for auth
$SignatureCert = Import-AdobeUMCert -CertThumbprint "0000000000000000000000000000000000000000" -CertStore "LocalMachine" #From windows store

#Client info from https://console.Adobe.io/
$ClientInformation = New-ClientInformation -APIKey "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" -OrganizationID "xxxxxxxxxxxxxxxxxxxxxxxx@AdobeOrg" -ClientSecret "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -TechnicalAccountID "xxxxxxxxxxxxxxxxxxxxxxxx@techacct.Adobe.com" -TechnicalAccountEmail "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@techacct.Adobe.com"

#Required auth token for further Adobe queries. (Is placed in ClientInformation)
Get-AdobeAuthToken -ClientInformation $ClientInformation -SignatureCert $SignatureCert

#Sync AD Group to Adobe
#You can get the groupid by running Get-AdobeGroups
$Request = New-SyncADGroupRequest -ADGroupName "My-AD-Group" -AdobeGroupName "All Apps Users" -ClientInformation $ClientInformation

#ToReview, uncomment
#Write-Host ($Request | ConvertTo-JSON -Depth 10)

#Send the generated request to Adobe
Send-UserManagementRequest -ClientInformation $ClientInformation -Requests $Request
```

You can examine the individual steps generated by examining the $Request object first.

## Additional Information

[Adobe.io UM API Documentation](https://Adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html)

[Adobe.io Authentication Docs](https://www.Adobe.io/authentication/auth-methods.html)

[JWT.io Java Web Token Documentation](https://jwt.io/)
