function Connect-MSCloudLoginDefenderForEndpoint
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $source = 'Connect-MSCloudLoginDefenderForEndpoint'

    if ($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthenticationType -eq 'CredentialsWithApplicationId' -or
        $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthenticationType -eq 'Credentials' -or
        $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthenticationType -eq 'CredentialsWithTenantId')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with user credentials' -Source $source
        Connect-MSCloudLoginDefenderForEndpointWithUser
    }
    elseif ($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthenticationType -eq 'ServicePrincipalWithSecret')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with Application Secret' -Source $source
        Connect-MSCloudLoginDefenderForEndpointWithAppSecret
    }
    elseif ($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthenticationType -eq 'ServicePrincipalWithThumbprint')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with Application Secret' -Source $source
        Connect-MSCloudLoginDefenderForEndpointWithCertificateThumbprint
    }
    elseif ($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthenticationType -eq 'AccessToken')
    {
        Add-MSCloudLoginAssistantEvent -Message 'Will try connecting with Access Token' -Source $source
        $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AccessTokens[0])
        $AccessTokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
        $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AccessToken = $AccessTokenValue
    }
}

function Connect-MSCloudLoginDefenderForEndpointWithUser
{
    [CmdletBinding()]
    param()

    $source = 'Connect-MSCloudLoginDefenderForEndpointWithUser'

    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.TenantId))
    {
        $tenantid = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.TenantId
    }
    $username = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Credentials.UserName
    $password = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Credentials.GetNetworkCredential().password


    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationId))
    {
        throw 'ApplicationId is required for this authentication type'
    }
    $clientId = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationId
    $uri = "$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthorizationUrl)/{0}/oauth2/token" -f $tenantid
    $body = "resource=$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.HostUrl)/&client_id=$clientId&grant_type=password&username={1}&password={0}" -f [System.Web.HttpUtility]::UrlEncode($password), $username

    # Request token through ROPC
    try
    {
        $managementToken = Invoke-RestMethod $uri `
            -Method POST `
            -Body $body `
            -ContentType 'application/x-www-form-urlencoded' `
            -ErrorAction SilentlyContinue

        $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
    }
    catch
    {
        if ($_.ErrorDetails.Message -like '*AADSTS50076*')
        {
            Add-MSCloudLoginAssistantEvent -Message 'Account used required MFA' -Source $source
            Connect-MSCloudLoginDefenderForEndpointWithUserMFA
        }
    }
}

function Connect-MSCloudLoginDefenderForEndpointWithUserMFA
{
    [CmdletBinding()]
    param()

    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.TenantId))
    {
        $tenantid = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Credentials.UserName.Split('@')[1]
    }
    else
    {
        $tenantId = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.TenantId
    }
    if ([System.String]::IsNullOrEmpty($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationId))
    {
        throw 'ApplicationId is required for this authentication type'
    }
    $clientId = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationId
    $deviceCodeUri = "$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthorizationUrl)/$tenantId/oauth2/devicecode"

    $body = @{
        client_id = $clientId
        resource  = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Scope
    }
    $DeviceCodeRequest = Invoke-RestMethod $deviceCodeUri `
        -Method POST `
        -Body $body

    Write-Host "`r`n$($DeviceCodeRequest.message)" -ForegroundColor Yellow

    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthorizationUrl)/$TenantId/oauth2/token"
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
    $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginDefenderForEndpointWithAppSecret
{
    [CmdletBinding()]
    param()


    $uri = "$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthorizationUrl)/{0}/oauth2/v2.0/token" -f $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.TenantId
    $body = "scope=$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Scope).default&client_id=$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationId)&client_secret=$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationSecret)&grant_type=client_credentials"

    # Request token through ROPC
    $managementToken = Invoke-RestMethod $uri `
        -Method POST `
        -Body $body `
        -ContentType 'application/x-www-form-urlencoded' `
        -ErrorAction SilentlyContinue

    $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AccessToken = $managementToken.token_type.ToString() + ' ' + $managementToken.access_token.ToString()
}

function Connect-MSCloudLoginDefenderForEndpointWithCertificateThumbprint
{
    [CmdletBinding()]
    param()

    $ProgressPreference = 'SilentlyContinue'
    $source = 'Connect-MSCloudLoginDefenderForEndpointWithCertificateThumbprint'

    Add-MSCloudLoginAssistantEvent -Message 'Attempting to connect to Whiteboard using CertificateThumbprint' -Source $source
    $tenantId = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.TenantId

    try
    {
        $Certificate = Get-Item "Cert:\CurrentUser\My\$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.CertificateThumbprint)" -ErrorAction SilentlyContinue

        if ($null -eq $Certificate)
        {
            Add-MSCloudLoginAssistantEvent 'Certificate not found in CurrentUser\My, trying LocalMachine\My' -Source $source

            $Certificate = Get-ChildItem "Cert:\LocalMachine\My\$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.CertificateThumbprint)" -ErrorAction SilentlyContinue

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
            aud = "$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthorizationUrl)/$TenantId/oauth2/token"

            # Expiration timestamp
            exp = $JWTExpiration

            # Issuer = your application
            iss = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationID

            # JWT ID: random guid
            jti = [guid]::NewGuid()

            # Not to be used before
            nbf = $NotBefore

            # JWT Subject
            sub = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationID
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
            client_id             = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.ApplicationID
            client_assertion      = $JWT
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            scope                 = $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.Scope
            grant_type            = 'client_credentials'
        }

        $Url = "$($Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AuthorizationUrl)/$TenantId/oauth2/v2.0/token"

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
        $Script:MSCloudLoginConnectionProfile.DefenderForEndpoint.AccessToken = 'Bearer ' + $Request.access_token
        Add-MSCloudLoginAssistantEvent -Message 'Successfully connected to the DefenderForEndpoint API using Certificate Thumbprint' -Source $source
    }
    catch
    {
        throw $_
    }
}
