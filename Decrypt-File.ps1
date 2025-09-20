# File Decryption with Azure Key Vault using RSA-OAEP-256
# This script decrypts a file that was encrypted using the Encrypt-File.ps1 script
# Authentication is done using service principal credentials from .env file

param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile = "test.csv.encrypted",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "test.csv.decrypted",
    
    [Parameter(Mandatory=$false)]
    [string]$KeyVaultUrl = "https://nixakvdev002.vault.azure.net/",
    
    [Parameter(Mandatory=$false)]
    [string]$KeyName = "nixkeydev001"
)

# Import required modules
Import-Module Az.KeyVault -Force
Import-Module Az.Accounts -Force

# Load environment variables from .env file
function Load-EnvironmentVariables {
    param([string]$EnvFilePath = ".env")
    
    if (Test-Path $EnvFilePath) {
        Get-Content $EnvFilePath | ForEach-Object {
            if ($_ -match "^\s*([^#][^=]*)\s*=\s*(.*)\s*$") {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim().Trim('"').Trim("'")
                [Environment]::SetEnvironmentVariable($name, $value)
                Write-Host "Loaded environment variable: $name" -ForegroundColor Green
            }
        }
    } else {
        throw "Environment file $EnvFilePath not found!"
    }
}

# Authenticate to Azure using service principal
function Connect-AzureWithServicePrincipal {
    param(
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$TenantId
    )
    
    try {
        Write-Host "Authenticating to Azure..." -ForegroundColor Yellow
        
        # Create PSCredential object
        $SecurePassword = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($ClientId, $SecurePassword)
        
        # Connect to Azure
        Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId $TenantId -WarningAction SilentlyContinue
        
        Write-Host "Successfully authenticated to Azure" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to authenticate to Azure: $($_.Exception.Message)"
        return $false
    }
}

# Get RSA private key from Azure Key Vault
function Get-RSAKeyFromKeyVault {
    param(
        [string]$KeyVaultUrl,
        [string]$KeyName
    )
    
    try {
        Write-Host "Getting RSA key from Key Vault..." -ForegroundColor Yellow
        
        # Extract key vault name from URL
        $KeyVaultName = ($KeyVaultUrl -replace "https://", "" -replace ".vault.azure.net/", "")
        
        # Get the key from Key Vault
        $Key = Get-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName
        
        if ($null -eq $Key) {
            throw "Key '$KeyName' not found in Key Vault '$KeyVaultName'"
        }
        
        Write-Host "Successfully retrieved key: $($Key.Name)" -ForegroundColor Green
        return $Key
    }
    catch {
        Write-Error "Failed to get key from Key Vault: $($_.Exception.Message)"
        throw
    }
}

# Decrypt file using RSA-OAEP-256
function Decrypt-FileWithRSA {
    param(
        [string]$InputFilePath,
        [string]$OutputFilePath,
        $RSAKey
    )
    
    try {
        Write-Host "Decrypting file: $InputFilePath" -ForegroundColor Yellow
        
        # Check if input file exists
        if (-not (Test-Path $InputFilePath)) {
            throw "Input file '$InputFilePath' not found!"
        }
        
        # Read encrypted data from JSON file
        $EncryptedJson = Get-Content $InputFilePath -Raw -Encoding UTF8
        $EncryptedData = $EncryptedJson | ConvertFrom-Json
        
        # Validate the structure
        if (-not $EncryptedData.EncryptedAESKey -or -not $EncryptedData.IV -or -not $EncryptedData.EncryptedContent) {
            throw "Invalid encrypted file format"
        }
        
        Write-Host "Encrypted with algorithm: $($EncryptedData.Algorithm)" -ForegroundColor Cyan
        Write-Host "Encrypted on: $($EncryptedData.Timestamp)" -ForegroundColor Cyan
        
        # Convert base64 data back to bytes (only IV and EncryptedContent)
        $IV = [Convert]::FromBase64String($EncryptedData.IV)
        $EncryptedContent = [Convert]::FromBase64String($EncryptedData.EncryptedContent)
        
        # For decryption, we need to use Azure Key Vault's decrypt operation
        # because we need access to the private key which stays in the HSM
        
        # Extract key vault name from URL
        $KeyVaultName = ($KeyVaultUrl -replace "https://", "" -replace ".vault.azure.net/", "")
        
        # Decrypt the AES key using Azure Key Vault
        Write-Host "Decrypting AES key using Azure Key Vault..." -ForegroundColor Yellow
        
        # Use Azure Key Vault REST API to decrypt the AES key
        # The EncryptedAESKey is already base64 encoded from the JSON file
        try {
            $DecryptResult = Invoke-AzRestMethod -Uri "https://$KeyVaultName.vault.azure.net/keys/$KeyName/decrypt?api-version=7.3" -Method POST -Payload (@{
                alg = "RSA-OAEP-256"
                value = $EncryptedData.EncryptedAESKey
            } | ConvertTo-Json)
            
            if ($DecryptResult.StatusCode -eq 200) {
                $ResponseContent = $DecryptResult.Content | ConvertFrom-Json
                $DecryptedAESKeyBase64 = $ResponseContent.value
                
                # Debug output
                Write-Host "Decrypted AES Key (Base64): $($DecryptedAESKeyBase64.Substring(0, [Math]::Min(50, $DecryptedAESKeyBase64.Length)))..." -ForegroundColor Cyan
                
                # Try to decode the base64 string
                try {
                    $AESKey = [Convert]::FromBase64String($DecryptedAESKeyBase64)
                    Write-Host "Successfully decoded AES key, length: $($AESKey.Length) bytes" -ForegroundColor Green
                } catch {
                    # If direct decode fails, try URL-safe base64 decode
                    $DecryptedAESKeyBase64 = $DecryptedAESKeyBase64.Replace('-', '+').Replace('_', '/')
                    while ($DecryptedAESKeyBase64.Length % 4 -ne 0) {
                        $DecryptedAESKeyBase64 += '='
                    }
                    $AESKey = [Convert]::FromBase64String($DecryptedAESKeyBase64)
                    Write-Host "Successfully decoded AES key with URL-safe conversion, length: $($AESKey.Length) bytes" -ForegroundColor Green
                }
            } else {
                throw "Key Vault decrypt operation failed with status: $($DecryptResult.StatusCode), Content: $($DecryptResult.Content)"
            }
        } catch {
            throw "Failed to decrypt AES key using Azure Key Vault: $($_.Exception.Message)"
        }
        
        # Decrypt the file content using AES
        Write-Host "Decrypting file content..." -ForegroundColor Yellow
        
        $AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Key = $AESKey
        $AES.IV = $IV
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $Decryptor = $AES.CreateDecryptor()
        $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedContent, 0, $EncryptedContent.Length)
        
        # Convert decrypted bytes back to string
        $DecryptedContent = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
        
        # Save decrypted content as bytes (for binary files)
        [System.IO.File]::WriteAllBytes($OutputFilePath, $DecryptedBytes)
        
        Write-Host "File successfully decrypted: $OutputFilePath" -ForegroundColor Green
        
        # Cleanup
        $AES.Dispose()
        $Decryptor.Dispose()
        
        return $true
    }
    catch {
        Write-Error "Failed to decrypt file: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
try {
    Write-Host "=== Azure Key Vault File Decryption ===" -ForegroundColor Cyan
    Write-Host "Input File: $InputFile" -ForegroundColor White
    Write-Host "Output File: $OutputFile" -ForegroundColor White
    Write-Host "Key Vault URL: $KeyVaultUrl" -ForegroundColor White
    Write-Host "Key Name: $KeyName" -ForegroundColor White
    Write-Host ""
    
    # Load environment variables
    Load-EnvironmentVariables
    
    # Get credentials from environment variables
    $ClientId = [Environment]::GetEnvironmentVariable("CLIENT_ID")
    $ClientSecret = [Environment]::GetEnvironmentVariable("CLIENT_SECRET")
    $TenantId = [Environment]::GetEnvironmentVariable("TENANT_ID")
    
    if (-not $ClientId -or -not $ClientSecret -or -not $TenantId) {
        throw "Missing required environment variables: CLIENT_ID, CLIENT_SECRET, or TENANT_ID"
    }
    
    # Authenticate to Azure
    if (-not (Connect-AzureWithServicePrincipal -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId)) {
        throw "Authentication failed"
    }
    
    # Get RSA key from Key Vault
    $RSAKey = Get-RSAKeyFromKeyVault -KeyVaultUrl $KeyVaultUrl -KeyName $KeyName
    
    # Decrypt the file
    if (Decrypt-FileWithRSA -InputFilePath $InputFile -OutputFilePath $OutputFile -RSAKey $RSAKey) {
        Write-Host ""
        Write-Host "=== Decryption Completed Successfully ===" -ForegroundColor Green
        Write-Host "Decrypted file saved as: $OutputFile" -ForegroundColor Green
    } else {
        throw "Decryption failed"
    }
}
catch {
    Write-Host ""
    Write-Host "=== Decryption Failed ===" -ForegroundColor Red
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    # Disconnect from Azure
    try {
        Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
    } catch {
        # Ignore disconnect errors
    }
}