# File Encryption with Azure Key Vault using RSA-OAEP-256
# This script encrypts a CSV file using RSA-OAEP-256 algorithm with a key from Azure Key Vault
# Authentication is done using service principal credentials from .env file

param(
    [Parameter(Mandatory=$false)]
    [string]$InputFile = "test.csv",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "test.csv.encrypted",
    
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

# Get RSA public key from Azure Key Vault
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

# Encrypt file using RSA-OAEP-256
function Encrypt-FileWithRSA {
    param(
        [string]$InputFilePath,
        [string]$OutputFilePath,
        $RSAKey,
        [string]$KeyVaultUrl,
        [string]$KeyName
    )
    
    try {
        Write-Host "Encrypting file: $InputFilePath" -ForegroundColor Yellow
        
        # Check if input file exists
        if (-not (Test-Path $InputFilePath)) {
            throw "Input file '$InputFilePath' not found!"
        }
        
        # Read file content as bytes (for binary files like ZIP)
        $FileBytes = Get-Content $InputFilePath -AsByteStream -Raw
        
        Write-Host "File size: $($FileBytes.Length) bytes" -ForegroundColor Cyan
        
        # For RSA encryption with Azure Key Vault, we'll use hybrid encryption:
        # 1. Generate a random AES key
        # 2. Encrypt the file with AES
        # 3. Encrypt the AES key with RSA using Azure Key Vault
        
        # Generate random AES key (256-bit)
        $AESKey = New-Object byte[] 32
        $RNG = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $RNG.GetBytes($AESKey)
        
        # Generate random IV for AES
        $IV = New-Object byte[] 16
        $RNG.GetBytes($IV)
        
        # Encrypt file content with AES
        $AES = [System.Security.Cryptography.Aes]::Create()
        $AES.Key = $AESKey
        $AES.IV = $IV
        $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $Encryptor = $AES.CreateEncryptor()
        $EncryptedContent = $Encryptor.TransformFinalBlock($FileBytes, 0, $FileBytes.Length)
        
        # Extract key vault name from URL
        $KeyVaultName = ($KeyVaultUrl -replace "https://", "" -replace ".vault.azure.net/", "")
        
        # Encrypt the AES key using Azure Key Vault with RSA-OAEP-256
        Write-Host "Encrypting AES key using Azure Key Vault..." -ForegroundColor Yellow
        
        # Convert AES key to base64 string for Key Vault API
        $AESKeyBase64 = [Convert]::ToBase64String($AESKey)
        
        # Use Azure Key Vault to encrypt the AES key
        try {
            $EncryptResult = Invoke-AzRestMethod -Uri "https://$KeyVaultName.vault.azure.net/keys/$KeyName/encrypt?api-version=7.3" -Method POST -Payload (@{
                alg = "RSA-OAEP-256"
                value = $AESKeyBase64
            } | ConvertTo-Json)
            
            if ($EncryptResult.StatusCode -eq 200) {
                $ResponseContent = $EncryptResult.Content | ConvertFrom-Json
                $EncryptedAESKeyBase64 = $ResponseContent.value
            } else {
                throw "Key Vault encrypt operation failed with status: $($EncryptResult.StatusCode)"
            }
        } catch {
            throw "Failed to encrypt AES key using Azure Key Vault: $($_.Exception.Message)"
        }
        
        # Create the final encrypted structure
        $EncryptedData = @{
            "EncryptedAESKey" = $EncryptedAESKeyBase64
            "IV" = [Convert]::ToBase64String($IV)
            "EncryptedContent" = [Convert]::ToBase64String($EncryptedContent)
            "Algorithm" = "RSA-OAEP-256 + AES-256-CBC"
            "Timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
        }
        
        # Save encrypted data as JSON
        $EncryptedJson = $EncryptedData | ConvertTo-Json -Depth 10
        Set-Content -Path $OutputFilePath -Value $EncryptedJson -Encoding UTF8
        
        Write-Host "File successfully encrypted: $OutputFilePath" -ForegroundColor Green
        
        # Cleanup
        $AES.Dispose()
        $Encryptor.Dispose()
        
        return $true
    }
    catch {
        Write-Error "Failed to encrypt file: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
try {
    Write-Host "=== Azure Key Vault File Encryption ===" -ForegroundColor Cyan
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
    
    # Encrypt the file
    if (Encrypt-FileWithRSA -InputFilePath $InputFile -OutputFilePath $OutputFile -RSAKey $RSAKey -KeyVaultUrl $KeyVaultUrl -KeyName $KeyName) {
        Write-Host ""
        Write-Host "=== Encryption Completed Successfully ===" -ForegroundColor Green
        Write-Host "Encrypted file saved as: $OutputFile" -ForegroundColor Green
    } else {
        throw "Encryption failed"
    }
}
catch {
    Write-Host ""
    Write-Host "=== Encryption Failed ===" -ForegroundColor Red
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