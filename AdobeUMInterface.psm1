#region Helper functions (General use functions)
<#
.SYNOPSIS
    Creates a new self-signed certificate for use with Adobe.

.PARAMETER DNSName
    Name to append to cert. Defaults to "ADOBEAUTH.<yourdomain>"

.PARAMETER ExpiryYears
    How long before the certificate expires in years. Defaults to 6

.PARAMETER Quiet
    Suppresses message on where to find cert

.OUTPUTS
    New certificate in the current user's certificate store

.NOTES
    This is required to sign a JWT that will authenticate the service account. 
    After a cert is created, export it without the private key and upload it to your service account's information page at https://console.adobe.io/
    Export the private key as a pfx file and store it somewhere. Ensure you know the password as it is required.
  
.EXAMPLE
    New-Cert
#>
function New-Cert
{
    Param
    (
        [string]$DNSName="ADOBEAUTH."+$env:USERDNSDOMAIN, 
        [int]$ExpiryYears=6,
        [switch]$Quiet
    )
    $CmdLetParam = (Get-Help -Name New-SelfSignedCertificate -Full).parameters.parameter | Where-Object {$_.name -eq "Provider"}
    if ($CmdLetParam) {
        $Cert=New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my -DnsName $DNSName -KeyFriendlyName $DNSName -NotAfter ([DateTime]::Now).AddYears($ExpiryYears) -HashAlgorithm "SHA512" -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"
        if (-not $Quiet) {
            Write-Host ("Your certificate has been created. You may find it in your certificate store. (Run MMC.exe as "+$env:USERNAME+"@"+$env:USERDNSDOMAIN+")")
            Write-Host "Add the certificate snap-in and you should find the new cert at 'Certificates - Current User\Personal\Certificates\$DNSName'"
            Write-Host "Right-Click the cert to export it with and without its private key"
        }
    } else {
        Write-Error "Your version of PowerShell/Windows does not support advanced features for the New-SelfSignedCertificate cmdlet. Please manually generate a certificate preferably using the `"Microsoft Enhanced RSA and AES Cryptographic Provider`" CSP."
    }
}

<#
.SYNOPSIS
    Load a certificate with a private key from file

.PARAMETER Password
    Password to open PFX

.PARAMETER CertPath
    Path to PFX File

.NOTES
    If you hard-code the password in a script utilizing this function, you should ensure the script is itself, somewhere secure

.EXAMPLE
    Import-PFXCert -Password "ASDF" -CertPath "C:\Cert.pfx"
#>
function Import-PFXCert
{
    [Obsolete("This cmdlet is obsolete. Please use Import-AdobeUMCert instead.")] 
    Param
    (
        [string]$Password,
        [ValidateScript({Test-Path -Path $_})]
        [Parameter(Mandatory=$true)][string]$CertPath
    )
    $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    $Collection.Import($CertPath, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
    return $Collection[0]
}

<#
.SYNOPSIS
    Load a certificate with a private key from either a file or from a certificate store

.PARAMETER Password
    Password to open PFX

.PARAMETER CertPath
    Path to PFX File

.PARAMETER CertThumbprint
    Thumbprint of the cert to load

.PARAMETER CertStore
    Which store to load cert from (LocalMachine or CurrentUser)

.NOTES
    If you hard-code the password in a script utilizing this function, you should ensure the script is itself, somewhere secure.
    The account running this function may need additional permissions to load private key from LocalMachine store.

.EXAMPLE
    Import-AdobeUMCert -Password "ASDF" -CertPath "C:\Cert.pfx"

.EXAMPLE
    Import-AdobeUMCert -CertThumbprint "00000000000000000000000000000000" -CertStore "LocalMachine"
#>
function Import-AdobeUMCert
{
    Param
    (
        [Parameter(Mandatory=$true,ParameterSetName='FromFile')][string]$Password,
        [ValidateScript({Test-Path -Path $_})]
        [Parameter(Mandatory=$true,ParameterSetName='FromFile')][string]$CertPath,
        [Parameter(Mandatory=$true,ParameterSetName='FromStore')][string]$CertThumbprint,
        [Parameter(Mandatory=$true,ParameterSetName='FromStore')][ValidateSet('CurrentUser','LocalMachine')]$CertStore
    )
    $Collection = @()
    if ($PSCmdlet.ParameterSetName -eq "FromStore") {
        #Convert cert store to the correct enum value
        if ($CertStore -eq "CurrentUser") {
            $CertStore = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        } elseif ($CertStore -eq "LocalMachine") {
            $CertStore = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        }
        #Open the certificate store
        $Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.x509Store -ArgumentList @($CertStore)
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        #Cleanup Thumbprint (Remove spaces, make uppercase, and remove hidden null characters from copy-paste)
        $CertThumbprint = $CertThumbprint.ToUpper() -replace "[^\w\d]",""

        #Now search for certificate by thumbprint
        $Collection = $Store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertThumbprint, $false)
        $Store.Dispose() #Make sure we cleanup after ourselves
    }
    elseif ($PSCmdlet.ParameterSetName -eq "FromFile")
    {
        #Load cert in by file
        $Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $Collection.Import($CertPath, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
    }
    if ($Collection.Length -lt 1) {
        Write-Error "Did not find any certificates in specified store"
        return $null
    }
    return $Collection[0]
}

<#
.SYNOPSIS
    Converts a byte[], to a Base64URL encoded string

.PARAMETER Item
    A byte[]
  
.EXAMPLE
    ConvertTo-Base64URL -Item "VGhpcyBpcyBhIHRlc3Q="
#>
function ConvertTo-Base64URL
{
    Param([Parameter(Mandatory=$true)]$Item)
    return [Convert]::ToBase64String($Item).Split("=")[0].Replace('+', '-').Replace('/', '_')
}

<#
.SYNOPSIS
    Converts a Base64Url string, to a decoded ASCII string

.PARAMETER Item
    A base64url string
  
.EXAMPLE
    ConvertFrom-Base64URL -Item "VGhpcyBpcyBhIHRlc3Q"
#>
function ConvertFrom-Base64URL
{
     Param([Parameter(Mandatory=$true)][string]$String)
     return [System.Text.ASCIIEncoding]::ASCII.GetString([convert]::FromBase64String((ConvertFrom-Base64URLToBase64 -String $String)))
}

<#
.SYNOPSIS
    Converts a Base64Url string, to a .Net base64 string

.PARAMETER Item
    A base64url string
  
.EXAMPLE
    ConvertFrom-Base64URLToBase64 -Item "VGhpcyBpcyBhIHRlc3Q"
#>
function ConvertFrom-Base64URLToBase64
{
     Param([Parameter(Mandatory=$true)][string]$String)
     $String = $String.Replace('-', '+').Replace('_', '/')
     while ((($String.Length)*6)%8-ne 0)
     {
         $String = $String+"="
     }
     return $String
}

<#
.SYNOPSIS
    Converts the [datetime] object passed into a java compliant numerical representation. (milliseconds since 1/1/1970)

.PARAMETER DateTimeObject
    A DateTime to be converted
  
.EXAMPLE
    ConvertTo-JavaTime -DateTimeObject ([DateTime]::Now)
#>
function ConvertTo-JavaTime
{
    Param([Parameter(Mandatory=$true)][DateTime]$DateTimeObject)
    #Take DateTime, convert to file time (100 nano second ticks since 1/1/1607). Subtract 1/1/1970 from that using the same 100nanoticks. Then multiply to convert from nanoticks to milliseconds since 1/1/1970. 
    return [int64](($DateTimeObject.ToFileTimeUtc()-[DateTime]::Parse("01/01/1970").ToFileTimeUtc())*0.0001)
}

<#
.SYNOPSIS
    Converts the java compliant numerical representation of time to a .net [datetime] object.

.PARAMETER JavaTime
    A JavaTime to be converted
  
.EXAMPLE
    ConvertFrom-JavaTime -JavaTime 1500000000000
#>
function ConvertFrom-JavaTime
{
    Param([Parameter(Mandatory=$true)][int64]$JavaTime)
    #Take the javatime, multiply it by 10000 to convert from millisecond ticks to 100 nanosecond ticks. Then add the 100 nano second tickets since 1970 to that number. This gives us the current file time.
    #Then convert file time to [datetime] object
    return [DateTime]::FromFileTimeUtc($JavaTime*10000+[DateTime]::Parse("01/01/1970").ToFileTimeUtc())
}


<#
.SYNOPSIS
    Unpacks a JWT object into it's header, and body components. (Human readable format)

.PARAMETER JWTObject
    JWT To unpack. In format of {Base64Header}.{Base64Body}.{Base64Signature}

.PARAMETER SigningCert
    A certificate with the necesary public key to verify signature block. Can be null, will not validate signature.

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    Expand-JWTInformation -JWTObject "xxxx.xxxx.xxx"
#>
function Expand-JWTInformation
{
    Param
    (
        [ValidateScript({$_.Split(".").Length -eq 3})]
        [Parameter(Mandatory=$true)][string]$JWTObject, 
        $SigningCert
    )
    $JWTParts = $JWTObject.Split(".")
    $Header =(ConvertFrom-Json -InputObject (ConvertFrom-Base64URL -String $JWTParts[0]));
    $RawData = [System.Text.ASCIIEncoding]::ASCII.GetBytes($JWTParts[0]+"."+$JWTParts[1])

    $Signature = [System.Convert]::FromBase64String((ConvertFrom-Base64URLToBase64 -String $JWTParts[2]))

    $Valid= $null
    if ($SigningCert -and $Header.alg.StartsWith("RS"))
    {
        $HAN=$null
        if ($Header.alg.EndsWith("256"))
        {
            $HAN = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        }
        elseif ($Header.alg.EndsWith("512"))
        {
            $Han = [System.Security.Cryptography.HashAlgorithmName]::SHA512
        }
        elseif ($Header.alg.EndsWith("384"))
        {
            $Han = [System.Security.Cryptography.HashAlgorithmName]::SHA384
        }
        if ($HAN)
        {
            $Valid = $SigningCert.PublicKey.Key.VerifyData($RawData, $Signature, $Han, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        else
        {
            Write-Warning "Hash algorithm not supported, the signature of the JWT was not verified."
        }
    }
    else 
    {
        Write-Warning "Either no certificate was passed to function, or Hash algorithm not supported, either way, the signature of the JWT was not verified."
    }
    return (New-Object -TypeName PSObject -ArgumentList @{Header=$Header;
                                                          Body=(ConvertFrom-Json -InputObject (ConvertFrom-Base64URL -String $JWTParts[1]));
                                                          SignatureValid=$Valid})
}


#endregion

#region Connection setup functions

<#
.SYNOPSIS
    Creates an object to contain client information such as service account details.

.PARAMETER APIKey 
    Your service account's APIkey/ClientID as returned by https://console.adobe.io/

.PARAMETER OrganizationID 
    Your OrganizationID as returned by https://console.adobe.io/

.PARAMETER ClientSecret 
    Your service account's ClientSecret  as returned by https://console.adobe.io/

.PARAMETER TechnicalAccountID 
    Your service account's TechnicalAccountID  as returned by https://console.adobe.io/

.PARAMETER TechnicalAccountEmail 
    Your service account's TechnicalAccountEmail  as returned by https://console.adobe.io/

.OUTPUTS
    ClientInformation object to be passed to further commands

.NOTES
    The information required by this function is provided to you by Adobe when you create an integration at https://console.adobe.io/
  
.EXAMPLE
    New-ClientInformation -APIKey "1111111111111222222333" -OrganizationID "22222222222222@AdobeOrg" -ClientSecret "xxxx-xxxx-xxxx-xxxx" -TechnicalAccountID "abcdf@techacct.adobe.com" -TechnicalAccountEmail "xxxx-xxxx-xxxx-xxxx@techacct.adobe.com"
#>
function New-ClientInformation
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$APIKey, 
        [Parameter(Mandatory=$true)][string]$OrganizationID, 
        [Parameter(Mandatory=$true)][string]$ClientSecret, 
        [Parameter(Mandatory=$true)][string]$TechnicalAccountID, 
        [Parameter(Mandatory=$true)][string]$TechnicalAccountEmail
    )
    return New-Object -TypeName PSObject -ArgumentList @{
        APIKey = $APIKey; # ClientID
        ClientID = $APIKey; # Alias, adobe flip flops on what they call this
        OrgID = $OrganizationID;
        ClientSecret = $ClientSecret;
        TechnicalAccountID = $TechnicalAccountID;
        TechnicalAccountEmail = $TechnicalAccountEmail;
        Token=$null;
    }
}

<#
.SYNOPSIS
    Adds an adobe auth token to the ClientInformation object passed to it

.PARAMETER ClientInformation 
    Your ClientInformation object

.PARAMETER SignatureCert 
    The cert that is attached to the specified account. Must have private key. Check which cert at https://console.adobe.io/

.PARAMETER AuthTokenURI 
    URI of the Adobe Auth Service. Defaults to https://ims-na1.adobelogin.com/ims/exchange/jwt/

.PARAMETER ExpirationInHours 
    When the request token should expire in hours. Defaults to 1

.OUTPUTS
    Attached auth token to ClientInformation.Token

.NOTES
    Create JWT https://www.adobe.io/apis/cloudplatform/console/authentication/createjwt/jwt_nodeJS.html
    https://github.com/lambtron/nextbus/blob/master/node_modules/jwt-simple/lib/jwt.js
    https://jwt.io/
  
.EXAMPLE
    Get-AdobeAuthToken -ClientInformation $MyClient -SignatureCert $Cert -ExpirationInHours 12
#>
function Get-AdobeAuthToken
{
    Param
    (
        [Parameter(Mandatory=$true)]$ClientInformation,
        [ValidateScript({$_.PrivateKey -ne $null})] 
        [Parameter(Mandatory=$true)]$SignatureCert, 
        [string]$AuthTokenURI="https://ims-na1.adobelogin.com/ims/exchange/jwt/", 
        [int]$ExpirationInHours=1
    )
    $PayLoad = New-Object -TypeName PSObject -Property @{
                                                            iss=$ClientInformation.OrgID;
                                                            sub=$ClientInformation.TechnicalAccountID;
                                                            aud="https://ims-na1.adobelogin.com/c/"+$ClientInformation.APIKey;
                                                            "https://ims-na1.adobelogin.com/s/ent_user_sdk"=$true;#MetaScope
                                                            exp=(ConvertTo-JavaTime -DateTimeObject ([DateTime]::Now.AddHours($ExpirationInHours)));
                                                        }
    #Header for the JWT
    $Header = ConvertTo-Json -InputObject (New-Object PSObject -Property @{"typ"="JWT";"alg"="RS256"}) -Compress
    
    #Body of the JWT. This is our actual request
    $JWT = ConvertTo-Base64URL -Item ([System.Text.ASCIIEncoding]::ASCII.GetBytes((ConvertTo-Json -InputObject $PayLoad -Compress)))
    
    #Join them together. as base64 strings, with a "." between them
    $JWT = (ConvertTo-Base64URL -Item ([System.Text.ASCIIEncoding]::ASCII.GetBytes($Header)))+"."+$JWT
    #Sign the data
    $JWTSig = ConvertTo-Base64URL -Item ($SignatureCert.PrivateKey.SignData([System.Text.ASCIIEncoding]::UTF8.GetBytes($JWT), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    #Append the signature. This is now a complete JWT
    $JWT = $JWT+"."+$JWTSig

    #Now we request the auth token
    $Body = "client_id=$($ClientInformation.APIKey)&client_secret=$($ClientInformation.ClientSecret)&jwt_token=$JWT"
    $ClientInformation.Token=Invoke-RestMethod -Method Post -Uri $AuthTokenURI -Body $Body -ContentType "application/x-www-form-urlencoded"
}

#endregion

<#
.SYNOPSIS
    Gets all users from the adobe API

.PARAMETER ClientInformation 
    Your ClientInformation object

.PARAMETER UM_Server 
    The adobe user management uri. Defaults to "https://usermanagement.adobe.io/v2/usermanagement/"

.PARAMETER Page
    You may manually specify a specific page to retrieve from Adobe. Otherwise a value < 0 will return all users
  
.EXAMPLE
    Get-AdobeUsers -ClientInformation $MyClient
#>
function Get-AdobeUsers
{
    Param
    (
        [string]$UM_Server="https://usermanagement.adobe.io/v2/usermanagement/", 
        [int]$Page=-1,
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation
    )
    #https://adobe-apiplatform.github.io/umapi-documentation/en/api/user.html
    #Store the results here
    $Results = @()

    #URI of the query endpoint
    $URIPrefix = $UM_Server+"users/$($ClientInformation.OrgID)/"

    $LoopToEnd = $true;
    if ($Page -lt 0) {
        $Page =0
    } else {
        $LoopToEnd = $false;
    }

    #Request headers
    $Headers = @{Accept="application/json";
             "Content-Type"="application/json";
             "x-api-key"=$ClientInformation.APIKey;
             Authorization="Bearer $($ClientInformation.Token.access_token)"}
    #Query, looping through each page, until we have all users.
    while($true)
    {
        try {
            $QueryResponse = Invoke-RestMethod -Method Get -Uri ($URIPrefix+$Page.ToString()) -Header $Headers
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq '429') {
            #https://adobe-apiplatform.github.io/umapi-documentation/en/api/ActionsRef.html#actionThrottle
            Write-Warning "Adobe is throttling our user query. This cmdlet will now sleep 30 seconds and continue."
            Start-Sleep -Seconds 30
            $Paused = $true
            }
        }
        if ($Paused -eq $true) {
            #reset paused flag so loop can try getting page again
            $Paused = $false
        }
        else {
            #Currently not required, but other queries will just keep dumping the same users as you loop though pages
            if ($Results -ne $null -and (@()+$Results.email).Contains($QueryResponse[0].email))
            {
                break;
            }
            $Results += $QueryResponse.users
            $Page++;
            #Different API endpoints have different ways of telling you if you are done.
            if ($QueryResponse.lastPage -eq $true -or $QueryResponse -eq $null -or $QueryResponse.Length -eq 0 -or -not $LoopToEnd)
            {
                break; 
            }
        }
    }
    return $Results
}

<#
.SYNOPSIS
    Gets a single user from the adobe API

.PARAMETER ClientInformation 
    Your ClientInformation object

.PARAMETER UM_Server 
    The adobe user management uri. Defaults to "https://usermanagement.adobe.io/v2/usermanagement/"

.PARAMETER UserID
    ID (Usually email) of the user to retrieve

.NOTES
    https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUser.html
  
.EXAMPLE
    Get-AdobeUser -ClientInformation $MyClient -UserID "john.doe@test.com"
#>
function Get-AdobeUser
{
    Param
    (
        [string]$UM_Server="https://usermanagement.adobe.io/v2/usermanagement/", 
        [Parameter(Mandatory=$true)][string]$UserID,
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation
    )
    #URI of the query endpoint
    $URIPrefix = "$($UM_Server)organizations/$($ClientInformation.OrgID)/users/$UserID"

    #Request headers
    $Headers = @{Accept="application/json";
             "Content-Type"="application/json";
             "x-api-key"=$ClientInformation.APIKey;
             Authorization="Bearer $($ClientInformation.Token.access_token)"}
    #Query
    while($true) {
        $QueryResponse = Invoke-RestMethod -Method Get -Uri $URIPrefix -Header $Headers
        if ($QueryResponse.error_code -ne $null -and $QueryResponse.error_code.ToString().StartsWith("429")) {
            #https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUsersWithPage.html#getUsersWithPageThrottle
            #I never got blocked testing this, not sure if this is needed, but just in case it does
            Write-Warning "Adobe is throttling our user query. This cmdlet will now sleep 1 minute and continue."
            Start-Sleep -Seconds 60
        }
        else
        {
            if ($QueryResponse.result.StartsWith("error") ) {
                Write-Error $QueryResponse.result;
                return $null
            }
            return $QueryResponse.user
        }
    }
}

<#
.SYNOPSIS
    Grab a list of all groups, or if provided an ID, returns the group related to the ID

.PARAMETER ClientInformation 
    Your ClientInformation object

.PARAMETER UM_Server 
    The adobe user management uri. Defaults to "https://usermanagement.adobe.io/v2/usermanagement/"

.PARAMETER GroupID
    If you wish to query for a single group instead, put the group ID here. [DEPRECATED!]
  
.EXAMPLE
    Get-AdobeGroups -ClientInformation $MyClient

.EXAMPLE
    Get-AdobeGroups -ClientInformation $MyClient -GroupID "222242"
#>
function Get-AdobeGroups
{
    Param
    (
        [string]$UM_Server="https://usermanagement.adobe.io/v2/usermanagement/",
        $GroupID=$null,
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation
    )
    $Results = @()
    if ($GroupID -eq $null)
    {
        $URIPrefix = $UM_SERVER+"groups/$($ClientInformation.OrgID)/"
    }
    else
    {
        $URIPrefix = "$UM_SERVER$($ClientInformation.OrgID)/user-groups/$GroupID"
        #https://adobe-apiplatform.github.io/umapi-documentation/en/api/group.html
        Write-Warning "This function is deprecated for use in getting a single group. There does not appear to be a replacement for this in the new API."
    }
    $Page =0

    #Request headers
    $Headers = @{Accept="application/json";
             "Content-Type"="application/json";
             "x-api-key"=$ClientInformation.APIKey;
             Authorization="Bearer $($ClientInformation.Token.access_token)"}
    if ($GroupID -eq $null)
    {
        while($true)
        {
            $QueryResponse = Invoke-RestMethod -Method Get -Uri ($URIPrefix+$Page.ToString()) -Header $Headers
            if ($QueryResponse.error_code -ne $null -and $QueryResponse.error_code.ToString().StartsWith("429")) {
                #https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUsersWithPage.html#getUsersWithPageThrottle
                #I never got blocked testing this, not sure if this is needed, but just in case it does
                Write-Warning "Adobe is throttling our query. This cmdlet will now sleep 1 minute and continue."
                Start-Sleep -Seconds 60
            }
            else {
                $Results += $QueryResponse.groups
                $Page++;
                if ($QueryResponse.lastPage -eq $true -or $QueryResponse -eq $null -or $QueryResponse.Length -eq 0)
                {
                    break
                }
            }
        }
    }
    else
    {
        $Results = Invoke-RestMethod -Method Get -Uri $URIPrefix -Header $Headers
    }
    return $Results
}


<#
.SYNOPSIS
    Grab all members of the specified group

.PARAMETER ClientInformation 
    Your ClientInformation object

.PARAMETER UM_Server 
    The adobe user management uri. Defaults to "https://usermanagement.adobe.io/v2/usermanagement/"

.PARAMETER GroupName
    The Name of the group to query
  
.EXAMPLE
    Get-AdobeGroupMembers -ClientInformation $MyClient -GroupName "All Apps Users"
#>
function Get-AdobeGroupMembers
{
    Param
    (
        [string]$UM_Server="https://usermanagement.adobe.io/v2/usermanagement/",
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation, 
        [Parameter(Mandatory=$true)][string]$GroupName
    )
    $Results = @()

    $URIPrefix = $UM_SERVER+"users/$($ClientInformation.OrgID)/{PAGE}/$GroupName" #Yes page before groupname...
    $Page =0

    #Request headers
    $Headers = @{Accept="application/json";
             "Content-Type"="application/json";
             "x-api-key"=$ClientInformation.APIKey;
             Authorization="Bearer $($ClientInformation.Token.access_token)"}

    while($true)
    {
        $QueryResponse = Invoke-RestMethod -Method Get -Uri ($URIPrefix.Replace("{PAGE}", $Page.ToString())) -Header $Headers
        if ($QueryResponse.error_code -ne $null -and $QueryResponse.error_code.ToString().StartsWith("429")) {
            #https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUsersWithPage.html#getUsersWithPageThrottle
            #I never got blocked testing this, not sure if this is needed, but just in case it does
            Write-Warning "Adobe is throttling our query. This cmdlet will now sleep 1 minute and continue."
            Start-Sleep -Seconds 60
        }
        else 
        {
            $Results += $QueryResponse.users
            $Page++;
            if ($QueryResponse.lastPage -eq $true -or $QueryResponse -eq $null -or $QueryResponse.users.Length -eq 0)
            {
                break
            }
        }
    }
    return $Results
}

<#
.SYNOPSIS
    Grab all admins of the specified group

.PARAMETER ClientInformation 
    Your ClientInformation object

.PARAMETER UM_Server 
    The adobe user management uri. Defaults to "https://usermanagement.adobe.io/v2/usermanagement/"

.PARAMETER GroupName
    The Name of the group to query
  
.EXAMPLE
    Get-AdobeGroupAdmins -ClientInformation $MyClient -GroupName "All Apps Users"
#>
function Get-AdobeGroupAdmins
{
    Param
    (
        $UM_Server="https://usermanagement.adobe.io/v2/usermanagement/",
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation, 
        [Parameter(Mandatory=$true)][string]$GroupName
    )
    #See https://www.adobe.io/apis/cloudplatform/usermanagement/docs/samples/samplequery.html
    $Results = @()

    $URIPrefix = $UM_SERVER+"users/$($ClientInformation.OrgID)/{PAGE}/_admin_$GroupName"
    $Page =0

    #Request headers
    $Headers = @{Accept="application/json";
             "Content-Type"="application/json";
             "x-api-key"=$ClientInformation.APIKey;
             Authorization="Bearer $($ClientInformation.Token.access_token)"}

    while($true)
    {
        $QueryResponse = Invoke-RestMethod -Method Get -Uri ($URIPrefix.Replace("{PAGE}", $Page.ToString())) -Header $Headers
        if ($QueryResponse.error_code -ne $null -and $QueryResponse.error_code.ToString().StartsWith("429")) {
            #https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUsersWithPage.html#getUsersWithPageThrottle
            #I never got blocked testing this, not sure if this is needed, but just in case it does
            Write-Warning "Adobe is throttling our query. This cmdlet will now sleep 1 minute and continue."
            Start-Sleep -Seconds 60
        }
        else 
        {
            $Results += $QueryResponse.users
            $Page++;
            if ($QueryResponse.lastPage -eq $true -or $QueryResponse -eq $null -or $QueryResponse.users.Length -eq 0)
            {
                break
            }
        }
    }
    return $Results
}


<#
.SYNOPSIS
    Creates a "CreateUserRequest" object. This object can then be converted to JSON and sent to create a new user

.PARAMETER FirstName
    User's First name

.PARAMETER LastName
    User's Last Name

.PARAMETER Email
    User's Email and ID

.PARAMETER Country
    Defaults to US. This cannot be changed later. (Per adobe documentation)

.PARAMETER IDType
    Specify the type of account to create. Valid values are enterprise,adobe,federated. Defaults to enterprise.

.PARAMETER Domain
    Only required if using federated access. If username is email, ommit this. Otherwise include for federated users.

.PARAMETER UserID
    Manually specify the user identity. Defaults to Email

.PARAMETER AdditionalActions
    An array of additional actions to add to the request. (Like add to group)

.PARAMETER OptionOnDuplicate
    Option to perform when a user already exists. Either ignoreIfAlreadyExists or updateIfAlreadyExists

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-CreateUserRequest -FirstName "John" -LastName "Doe" -Email "John.Doe@domain.com" -IDType enterprise

.EXAMPLE
    New-CreateUserRequest -FirstName "John" -LastName "Doe" -UserID "John.Doe" -Email "John.Doe@domain.com" -IDType federated

#>
function New-CreateUserRequest
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$FirstName, 
        [Parameter(Mandatory=$true)][string]$LastName, 
        [Parameter(Mandatory=$true)][string]$Email,
        [string]$UserID=$Email,
        [ValidateSet("enterprise","federated", "adobe")]
        $IDType="enterprise",
        $Domain,
        [string]$Country="US", 
        $AdditionalActions=@(),
        [ValidateSet("ignoreIfAlreadyExists","updateIfAlreadyExists")] 
        $OptionOnDuplicate="ignoreIfAlreadyExists"
    )
    
    #Properties required for all account types
    $IDParameters = New-Object -TypeName PSObject -Property @{email=$Email;country=$Country;firstname=$FirstName;lastname=$LastName}

    #Add option if it exists
    if ($OptionOnDuplicate -ne $null) {
        $IDParameters | Add-Member -MemberType NoteProperty -Name "option" -Value $OptionOnDuplicate
    }

    $CreateAction = $null;
    if ($IDType -eq "enterprise") {
        $CreateAction = New-Object -TypeName PSObject -Property @{createEnterpriseID=$IDParameters}
    }
    elseif ($IDType -eq "federated") {
        $CreateAction = New-Object -TypeName PSObject -Property @{createFederatedID=$IDParameters}
    }
    elseif ($IDType -eq "adobe") {
        $CreateAction = New-Object -TypeName PSObject -Property @{addAdobeID=$IDParameters}
    }

    #Add any additional actions
    $AdditionalActions = @()+ $CreateAction + $AdditionalActions

    #Build and return the new request
    $Request = New-Object -TypeName PSObject -Property @{user=$UserID;do=@()+$AdditionalActions}
    #Adobe and federated require another field
    if ($Domain -ne $null) {
        $Request | Add-Member -MemberType NoteProperty -Name "domain" -Value $Domain
    }
    if ($IDType -eq "adobe") {
        $Request | Add-Member -MemberType NoteProperty -Name "useAdobeID" -Value "true"
    }
    return $Request;
}

<#
.SYNOPSIS
    Creates a "RemoveUserRequest" object. This object can then be converted to JSON and sent to remove a user from adobe

.PARAMETER UserName
    User's ID, usually e-mail

.PARAMETER Domain
    User's domain, only required for some types of federated id

.PARAMETER AdditionalActions
    An array of additional actions to add to the request. (Like add to group)

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-RemoveUserRequest -UserName "john.doe@domain.com"
#>
function New-RemoveUserRequest
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$UserName,
        [string]$Domain,
        $AdditionalActions=@()
    )

    $RemoveAction = New-Object -TypeName PSObject -Property @{removeFromOrg=(New-Object -TypeName PSObject)}

    $AdditionalActions = @() + $RemoveAction + $AdditionalActions

    #Build and return request
    $Request = New-Object -TypeName PSObject -Property @{user=$UserName;do=@()+$AdditionalActions}
    if ($Domain) {
        $Request | Add-Member -MemberType NoteProperty -Name "domain" -Value $Domain
    }
    return $Request
}

<#
.SYNOPSIS
    Creates a request to remove a user from an Adobe group. This will need to be posted after being converted to a JSON

.PARAMETER UserName
    User's ID, usually e-mail

.PARAMETER GroupName
    Name of the group to remove the user from

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-RemoveUserFromGroupRequest -UserName "john.doe@domain.com" -GroupName "My User Group"
#>
function New-RemoveUserFromGroupRequest
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$UserName,
        [string]$Domain,
        [Parameter(Mandatory=$true)]$GroupName
    )

    $RemoveMemberAction = New-GroupUserRemoveAction -Groups $GroupName

    #Build and return request
    $Request = New-Object -TypeName PSObject -Property @{user=$UserName;do=@()+$RemoveMemberAction}
    if ($Domain) {
        $Request | Add-Member -MemberType NoteProperty -Name "domain" -Value $Domain
    }
    return $Request
}

<#
.SYNOPSIS
    Creates a "Add to group" action. Actions fall under requests. This will have to be added to a request, then json'd and submitted to adobe's API

.PARAMETER Groups
    An array of groups that something should be added to

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-GroupUserAddAction -Groups "My User Group"
#>
function New-GroupUserAddAction
{
    Param
    (
        [Parameter(Mandatory=$true)]$Groups
    )

    $Params = New-Object -TypeName PSObject -Property @{group=@()+$Groups}

    return (New-Object -TypeName PSObject -Property @{add=$Params})
}

<#
.SYNOPSIS
    Creates a "Remove from group" action. Actions fall under requests. This will have to be added to a request, then json'd and submitted to adobe's API

.PARAMETER Groups
    An array of groups that something should be removed from

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-GroupUserRemoveAction -Groups "My User Group"
#>
function New-GroupUserRemoveAction
{
    Param
    (
        [Parameter(Mandatory=$true)]$Groups
    )

    $Params = New-Object -TypeName PSObject -Property @{group=@()+$Groups}

    return (New-Object -TypeName PSObject -Property @{remove=$Params})
}

<#
.SYNOPSIS
    Creates a "Add user to group" request. This will need to be json'd and sent to adobe

.PARAMETER Groups
    An array of groups that something should be added to

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-AddToGroupRequest -Groups "My User Group" -User "John.Doe@domain.com"
#>
function New-AddToGroupRequest
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$User, 
        [Parameter(Mandatory=$true)]$Groups
    )
    $GroupAddAction = New-GroupUserAddAction -Groups $Groups
    return (New-Object -TypeName PSObject -Property @{user=$User;do=@()+$GroupAddAction})
}

<#
.SYNOPSIS
    Creates a "Remove user from group" request. This will need to be json'd and sent to adobe

.PARAMETER Groups
    An array of groups that something should be removed from

.NOTES
    See https://adobe-apiplatform.github.io/umapi-documentation/en/RefOverview.html
    This should be posted to https://usermanagement.adobe.io/v2/usermanagement/action/{myOrgID}
  
.EXAMPLE
    New-RemoveFromGroupRequest -Groups "My User Group" -User "John.Doe@domain.com"
#>
function New-RemoveFromGroupRequest
{
    Param
    (
        [Parameter(Mandatory=$true)][string]$User, 
        [Parameter(Mandatory=$true)]$Groups
    )
    
    $GroupRemoveAction = New-GroupUserRemoveAction -GroupNames $Groups
    return return (New-Object -TypeName PSObject -Property @{user=$User;do=@()+$GroupRemoveAction})
}

<#
.SYNOPSIS
    Sends a request, or array of requests, to adobe's user management endpoint

.PARAMETER ClientInformation
    ClientInformation object containing service account info and token

.PARAMETER Requests
    An array of requests to send to adobe

.NOTES
    See the New-*Request
  
.EXAMPLE
    Send-UserManagementRequest -ClientInformation $MyClientInfo -Requests (New-CreateUserRequest -FirstName "John" -LastName "Doe" -Email "john.doe@domain.com" -Country="US")
#>
function Send-UserManagementRequest
{
    Param
    (
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation,
        $Requests
    )
    #Ensure is array
    $Request = @()+$Requests

    #region Split request into 10 command chunks
    #Larger queries kept returning invalid JSON format errors from adobe
    $QueChunks = 10
    $RequestQue = @()
    $Count =0
    $NextQueEntry = @()
    for ($I = 0; $I -lt $Request.Length; $I++) {
        $NextQueEntry +=$Request[$I]
        $Count++;
        if ($Count -ge $QueChunks) {
            $RequestQue += ,$NextQueEntry
            $NextQueEntry = @()
            $Count=0
        }
    }
    #Capture last chunk if it was not an exact multiple of 100
    if ($NextQueEntry.Length -gt 0) {
        $RequestQue += ,$NextQueEntry
        $NextQueEntry = @()
        $Count=0
    }
    #endregion

    #Prepare Headers
    #https://adobe-apiplatform.github.io/umapi-documentation/en/api/ActionsRef.html
    $URI = "https://usermanagement.adobe.io/v2/usermanagement/action/$($ClientInformation.OrgID)"
    $Headers = @{Accept="application/json";
            "Content-Type"="application/json";
            "x-api-key"=$ClientInformation.APIKey;
            Authorization="Bearer $($ClientInformation.Token.access_token)"}

    #Loop through the request que and send off the requests
    $ResultArray=@()
    Write-Progress -Activity "Sending requests" -Status "(0/$($RequestQue.Length))" -PercentComplete 0
    for ($I=0; $I -lt $RequestQue.Length; $I++) {
        $Request = ConvertTo-Json -InputObject $RequestQue[$I] -Depth 10 -Compress

        $Result = Invoke-RestMethod -Method Post -Uri $URI -Body $Request -Header $Headers
        $ResultArray+=$Result
        if ($Result.error_code -ne $null -and $Result.error_code.ToString().StartsWith("429")) {
            $I--; #Decrement to retry current request after timeout
            #https://adobe-apiplatform.github.io/umapi-documentation/en/api/getUsersWithPage.html#getUsersWithPageThrottle
            #I never got blocked testing this, not sure if this is needed, but just in case it is
            Write-Warning "Adobe is throttling our user query. This cmdlet will now sleep 1 minute and continue."
            Start-Sleep -Seconds 60
        } elseif ($Result.error_code -ne $null) {
            Write-Warning -Message "Error occured in request, $($Result.error_code)"
        }
        Write-Progress -Activity "Sending requests" -Status "($I/$($RequestQue.Length))" -PercentComplete (100*$I/$RequestQue.Length)
    }
    Write-Progress -Activity "Sending requests" -Status "Done" -PercentComplete 100 -Completed
    return $ResultArray
}

<#
    .SYNOPSIS
        Creates an array of requests that, when considered together, ensures an Adobe group will mirror an AD group
    
    .DESCRIPTION
        A detailed description of the New-SyncADGroupRequest function.
    
    .PARAMETER ADGroupName
        Active Directory Group Identifier (Name or DN). The source group to mirror to adobe
    
    .PARAMETER AdobeGroupName
        Adobe group Name
    
    .PARAMETER RecurseADGroupMembers
        If specified, will pull all users in all groups in and under the specified ADGroup
    
    .PARAMETER DeleteRemovedMembers
        Removes users from the Adobe Console if they have been removed from the group
    
    .PARAMETER CreateAsFederated
        If a new user needs to be created in Adobe, this switch creates them with a federatedID instead of an EnterpriseID
    
    .PARAMETER ClientInformation
        Service account information including token
    
    .EXAMPLE
        New-SyncADGroupRequest -ADGroupName "SG-My-Adobe-Users" -AdobeGroupName "All Apps Users" -ClientInformation $MyClientInfo
    
    .NOTES
        If you accidently remove an admin account using DeleteRemovedMembers, you can still recover using the API.
#>
Function New-SyncADGroupRequest {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ADGroupName,
        [Parameter(Mandatory = $true)]
        [string]
        $AdobeGroupName,
        [switch]
        $RecurseADGroupMembers,
        [switch]
        $DeleteRemovedMembers,
        [switch]
        $CreateAsFederated,
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                $_.Token -ne $null
            })]
        $ClientInformation
    )
    
    #Grab a list of users in the Active Directory group
    $ADGroupMembers = (Get-ADGroupMember -Identity $ADGroupName -Recursive:$RecurseADGroupMembers).Where{
        $_.ObjectClass -eq "user" -or $_.ObjectClass -eq 'inetOrgPerson'
    }
    #Get extended property data on all users. (So we can get e-mail)
    $ADUsers = [System.Collections.Generic.List[PSObject]]::New()
    ForEach ($ADGroupMember In $ADGroupMembers) {
        $ADUsers.Add($(Get-ADUser -Identity $ADGroupMember.distinguishedName -Properties mail))
    }
    #Grab a list of users from the adobe group
    $Members = [System.Collections.Generic.List[String]]::New()
    $ADBMembers = Get-AdobeGroupMembers -ClientInformation $ClientInformation -GroupName $AdobeGroupName
    If ($ADBMembers -ne $null) {
        If ($ADBMembers.email.count -gt 1) {
            $ADBMembers.email.foreach{
                $Members.Add($_.ToLower())
            }
        }
        Else {
            $Members.Add($ADBMembers.email.ToLower())
        }
    }
    
    #Grab all Adobe Users 
    $AdobeUsers = Get-AdobeUsers -ClientInformation $ClientInformation
    
    #Results
    $Request = [System.Collections.Generic.List[PSObject]]::New()
    
    #Find missing users, and create requests to add them to adobe
    ForEach ($ADUser In $ADUsers) {
        #If adobe group does not contain ad user
        If ($Members.Count -le 0 -or -not $Members.Contains($ADUser.mail.ToLower())) {
            #Check if user already exists
            If ($AdobeUsers.email -contains $ADUser.mail.ToLower()) {
                $Request.Add($(New-AddToGroupRequest -User $ADUser.mail.ToLower() -Groups $AdobeGroupName))
            }
            Else {
                $AddToGroup = New-GroupUserAddAction -Groups $AdobeGroupName
                #Need to add
                If ($CreateAsFederated) {
                    $Request.Add($(New-CreateUserRequest -FirstName $ADUser.GivenName -LastName $ADUser.SurName -Email $ADUser.mail.ToLower() -Country "US" -AdditionalActions $AddToGroup -IDType federated))
                }
                Else {
                    $Request.Add($(New-CreateUserRequest -FirstName $ADUser.GivenName -LastName $ADUser.SurName -Email $ADUser.mail.ToLower() -Country "US" -AdditionalActions $AddToGroup))
                }
            }
        }
    }
    #Find excess members and create requests to remove them
    ForEach ($Member In $Members) {
        If (-not (@() + ($ADUsers.mail.ForEach{
                        $_.ToLower()
                    })).Contains($Member)) {
            If ($DeleteRemovedMembers) {
                #Remove user from Adobe Console entirely
                $Request.Add($(New-RemoveUserRequest -UserName $Member))
            }
            Else {
                #Need to remove
                $Request.Add($(New-RemoveUserFromGroupRequest -UserName $Member -GroupName $AdobeGroupName))
            }
        }
    }
    #return our list of requests
    Return $Request
}

<#
.SYNOPSIS
    Creates an array of requests that, when considered together, removes all users that are not admins, and not part of any user groups

.PARAMETER ClientInformation
    Service account information including token
  
.EXAMPLE
    New-RemoveUnusedAbobeUsersRequest -ClientInformation $MyClientInfo
#>
function New-RemoveUnusedAbobeUsersRequest
{
    Param
    (
        [ValidateScript({$_.Token -ne $null})]
        [Parameter(Mandatory=$true)]$ClientInformation
    )
    $AdobeUsers = Get-AdobeUsers -ClientInformation $ClientInformation
    $Requests = @()
    foreach ($User in $AdobeUsers)
    {
        if (($User.groups -eq $null -or $User.groups.length -eq 0) -and 
            ($User.adminRoles -eq $null -or $User.adminRoles.length -eq 0))
        {
            #Account not used
            $Requests+=New-RemoveUserRequest -UserName $User.username
        }
    }
    return $Requests
}

Export-ModuleMember -Function "New-Cert", "Import-PFXCert", "ConvertTo-Base64URL", "ConvertFrom-Base64URL", "ConvertFrom-Base64URLToBase64", 
                                "ConvertTo-JavaTime", "ConvertFrom-JavaTime", "New-ClientInformation", "Get-AdobeAuthToken", "Get-AdobeUsers", 
                                "Get-AdobeGroups", "Get-AdobeGroupMembers", "Get-AdobeGroupAdmins", "New-CreateUserRequest", "New-RemoveUserRequest", 
                                "New-RemoveUserFromGroupRequest", "New-GroupUserAddAction", "New-GroupUserRemoveAction", "New-AddToGroupRequest", 
                                "New-RemoveFromGroupRequest", "Expand-JWTInformation", "Send-UserManagementRequest", "New-SyncADGroupRequest", 
                                "New-RemoveUnusedAbobeUsersRequest", "Get-AdobeUser", "Import-AdobeUMCert"
