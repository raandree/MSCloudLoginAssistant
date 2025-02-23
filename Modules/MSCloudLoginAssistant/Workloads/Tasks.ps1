function Connect-MSCloudLoginTasks
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $source = 'Connect-MSCloudLoginTasks'

    if ($Script:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Script:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'Credentials' -or
        $Script:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with user credentials' -Source $source
        Connect-MSCloudLoginTasksWithUser
    }
    elseif ($Script:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'ServicePrincipalWithSecret')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with Application Secret' -Source $source
        Connect-MSCloudLoginTasksWithAppSecret
    }
    elseif ($Script:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with Application Secret' -Source $source
        Connect-MSCloudLoginTasksWithCertificateThumbprint
    }
    elseif ($Script:MSCloudLoginConnectionProfile.Tasks.AuthenticationType -eq 'AccessToken')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with Access Token' -Source $source
        $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Script:MSCloudLoginConnectionProfile.Tasks.AccessTokens[0])
        $AccessTokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
        $Script:MSCloudLoginConnectionProfile.Tasks.AccessToken = $AccessTokenValue
    }
}

function Connect-MSCloudLoginTasksWithUser
{
    [CmdletBinding()]
    param()

    $source = 'Connect-MSCloudLoginTasksWithUser'

    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.Tasks.TenantId))
    {
        $tenantid = $Script:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.Tasks.TenantId
    }
    $username = $Script:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName
    $password = $Script:MSCloudLoginConnectionProfile.Tasks.Credentials.GetNetworkCredential().password

    $clientId = '9ac8c0b3-2c30-497c-b4bc-cadfe9bd6eed'
    $uri = "$($Script:MSCloudLoginConnectionProfile.Tasks.AuthorizationUrl)/{0}/oauth2/token" -f $tenantid
    $body = "resource=$($Script:MSCloudLoginConnectionProfile.Tasks.HostUrl)/&client_id=$clientId&grant_type=password&username={1}&password={0}" -f [System.Web.HttpUtility]::UrlEncode($password), $username

    # Request token through ROPC
    try
    {
        $managementToken = Invoke-RestMethod $uri `
            -Method POST `
            -Body $body `
            -ContentType 'application/x-www-form-urlencoded' `
            -ErrorAction SilentlyContinue

        $Script:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
    }
    catch
    {
        if ($_.ErrorDetails.Message -like '*AADSTS50076*')
        {
            Add-MSCloudLoginAssistantEvent -Message 'Account used required MFA' -Source $source
            Connect-MSCloudLoginTasksWithUserMFA
        }
    }
}

function Connect-MSCloudLoginTasksWithUserMFA
{
    [CmdletBinding()]
    param()

    $source = 'Connect-MSCloudLoginTasksWithUserMFA'

    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.Tasks.TenantId))
    {
        $tenantid = $Script:MSCloudLoginConnectionProfile.Tasks.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.Tasks.TenantId
    }
    $clientId = '9ac8c0b3-2c30-497c-b4bc-cadfe9bd6eed'
    $deviceCodeUri = "$($Script:MSCloudLoginConnectionProfile.Tasks.AuthorizationUrl)/$tenantId/oauth2/devicecode"

    $body = @{
        client_id = $clientId
        resource  = $Script:MSCloudLoginConnectionProfile.Tasks.ResourceUrl
    }
    $DeviceCodeRequest = Invoke-RestMethod $deviceCodeUri `
        -Method POST `
        -Body $body

    Add-MSCloudLoginAssistantEvent -Message "`r`n$($DeviceCodeRequest.message)" -Source $source

    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "$($Script:MSCloudLoginConnectionProfile.Tasks.AuthorizationUrl)/$TenantId/oauth2/token"
        Body   = @{
            grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
            code       = $DeviceCodeRequest.device_code
            client_id  = $clientId
        }
    }
    $TimeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ([string]::IsNullOrEmpty($managementToken.access_token))
    {
        if ($TimeoutTimer.Elapsed.TotalSeconds -gt 300)
        {
            throw 'Login timed out, please try again.'
        }
        $managementToken = try
        {
            Invoke-RestMethod @TokenRequestParams -ErrorAction Stop
        }
        catch
        {
            $Message = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($Message.error -ne 'authorization_pending')
            {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
    $Script:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginTasksWithAppSecret
{
    [CmdletBinding()]
    param()

    $uri = "$($Script:MSCloudLoginConnectionProfile.Tasks.AuthorizationUrl)/{0}/oauth2/token" -f $Script:MSCloudLoginConnectionProfile.Tasks.TenantId
    $body = "resource=$($Script:MSCloudLoginConnectionProfile.Tasks.HostUrl)/&client_id=$($Script:MSCloudLoginConnectionProfile.Tasks.ApplicationId)&client_secret=$($Script:MSCloudLoginConnectionProfile.Tasks.ApplicationSecret)&grant_type=client_credentials"

    # Request token through ROPC
    $managementToken = Invoke-RestMethod $uri `
        -Method POST `
        -Body $body `
        -ContentType 'application/x-www-form-urlencoded' `
        -ErrorAction SilentlyContinue

    $Script:MSCloudLoginConnectionProfile.Tasks.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginTasksWithCertificateThumbprint
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $source = 'Connect-MSCloudLoginTasksWithCertificateThumbprint'

    Add-MSCloudLoginAssistantEvent -Message 'Attempting to connect to Whiteboard using CertificateThumbprint' -Source $source
    $tenantId = $Script:MSCloudLoginConnectionProfile.Tasks.TenantId

    try
    {
        $Certificate = Get-Item "Cert:\CurrentUser\My\$($Script:MSCloudLoginConnectionProfile.Tasks.CertificateThumbprint)" -ErrorAction SilentlyContinue

        if ($null -eq $Certificate)
        {
            Add-MSCloudLoginAssistantEvent 'Certificate not found in CurrentUser\My, trying LocalMachine\My' -Source $source

            $Certificate = Get-ChildItem "Cert:\LocalMachine\My\$($Script:MSCloudLoginConnectionProfile.Tasks.CertificateThumbprint)" -ErrorAction SilentlyContinue

            if ($null -eq $Certificate)
            {
                throw 'Certificate not found in LocalMachine\My nor CurrentUser\My'
            }
        }
        # Create base64 hash of certificate
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        # Create JWT timestamp for expiration
        $StartDate = (Get-Date '1970-01-01T00:00:00Z' ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)

        # Create JWT validity start timestamp
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)

        # Create JWT header
        $JWTHeader = @{
            alg = 'RS256'
            typ = 'JWT'
            # Use the CertificateBase64Hash and replace/strip to match web encoding of base64
            x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
        }

        # Create JWT payload
        $JWTPayLoad = @{
            # What endpoint is allowed to use this JWT
            aud = "$($Script:MSCloudLoginConnectionProfile.Tasks.AuthorizationUrl)/$TenantId/oauth2/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $Script:MSCloudLoginConnectionProfile.Tasks.ApplicationID

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $Script:MSCloudLoginConnectionProfile.Tasks.ApplicationID
        }

        # Convert header and payload to base64
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

        $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

        # Join header and Payload with "." to create a valid (unsigned) JWT
        $JWT = $EncodedHeader + '.' + $EncodedPayload

        # Get the private key object of your certificate
        $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))

        # Define RSA signature and hashing algorithm
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

        # Create a signature of the JWT
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)
        ) -replace '\+', '-' -replace '/', '_' -replace '='

        # Join the signature to the JWT with "."
        $JWT = $JWT + '.' + $Signature

        # Create a hash with body parameters
        $Body = @{
            client_id             = $Script:MSCloudLoginConnectionProfile.Tasks.ApplicationID
            client_assertion      = $JWT
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            scope                 = $Script:MSCloudLoginConnectionProfile.Tasks.Scope
            grant_type            = 'client_credentials'
        }

        $Url = "$($Script:MSCloudLoginConnectionProfile.Tasks.AuthorizationUrl)/$TenantId/oauth2/v2.0/token"

        # Use the self-generated JWT as Authorization
        $Header = @{
            Authorization = "Bearer $JWT"
        }

        # Splat the parameters for Invoke-Restmethod for cleaner code
        $PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded'
            Method      = 'POST'
            Body        = $Body
            Uri         = $Url
            Headers     = $Header
        }

        $Request = Invoke-RestMethod @PostSplat

        # View access_token
        $Script:MSCloudLoginConnectionProfile.Tasks.AccessToken = 'Bearer ' + $Request.access_token
        Add-MSCloudLoginAssistantEvent -Message 'Successfully connected to the Tasks API using Certificate Thumbprint' -Source $source
    }
    catch
    {
        throw $_
    }
}
