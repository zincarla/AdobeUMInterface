# AdobeUMInterface
A PowerShell framework for communicating with Adobe's User Management API

## General Usage Instructions

1) Create a service account and link it to your User Management binding. (Do this at https://console.adobe.io)
2) Create a PKI certificate. You can create a self signed one using the provided Create-Cert command
3) Export the PFX and a public certificate from your generated certificate. 
4) Upload the public cert to the account you created in step 1.
5) Using the information adobe gave you in step 1, call New-ClientInformation and provide it the necessary information. (APIKey, ClientSecret, etc)
6) Load the PFX certificate. You can do this with the provided Load-PFXCert function.
7) Call Get-AdobeAuthToken, to request an auth token from adobe.
8) Utilize the other functions, and your ClientInformation variable to make further queries against your Adobe users.

A complete example of the calls you should make after step 5 are below
```
#Load the Auth cert generated with Create-Cert
$SignatureCert = Load-PFXCert -Password "MyPassword" -CertPath "C:\Certs\AdobeAuthPrivate.pfx"

#Client info from https://console.adobe.io/
$ClientInformation = New-ClientInformation -APIKey "1234123412341234" -OrganizationID "1234123412341234@AdobeOrg" -ClientSecret "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx" `
    -TechnicalAccountID "12341234123412341234B@techacct.adobe.com" -TechnicalAccountEmail "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx6@techacct.adobe.com"

#Required auth token for further adobe queries. (Is placed in ClientInformation)
Get-AdobeAuthToken -ClientInformation $ClientInformation -SignatureCert $SignatureCert

#List Users
$Users = Get-AdobeUsers -ClientInformation $ClientInformation

#Add a new user, and add them to a group in one adobe request
$GroupAddAction = Create-GroupAddAction -Groups "All Apps Users"
$Request = Create-CreateUserRequest -FirstName "John" -LastName "Doe" -Email "John.Doe@domain.com" -AdditionalActions $GroupAddAction

#Send the generated request to adobe
Send-UserManagementRequest -ClientInformation $ClientInformation -Requests $Request
```

# Additional Information
https://www.adobe.io/apis/cloudplatform/usermanagement/docs/api/overview.html

https://www.adobe.io/apis/cloudplatform/console/authentication/createjwt/jwt_java.html

https://jwt.io/
