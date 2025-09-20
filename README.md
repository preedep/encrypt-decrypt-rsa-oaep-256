# 🔐 Azure Key Vault File Encryption/Decryption with PowerShell

[🇹🇭 ไทย](#thai) | [🇺🇸 English](#english)

---

## 🇹🇭 Thai {#thai}

โปรเจคนี้เป็น PowerShell scripts สำหรับ **encrypt และ decrypt ไฟล์ทุกประเภท** (CSV, ZIP, PDF, etc.) โดยใช้ **Azure Key Vault** กับ **RSA-OAEP-256 + AES-256-CBC** algorithm

### 🎯 **จุดประสงค์**
- เข้ารหัสไฟล์สำคัญก่อนส่งหรือเก็บข้อมูล
- ใช้ Azure Key Vault เป็น central key management
- รองรับไฟล์ทุกขนาด (เล็กหรือใหญ่)
- ความปลอดภัยระดับ enterprise

### 🏗️ **วิธีการทำงาน**
```
📁 Input File → 🔒 Encrypt → 📦 JSON File → 🔓 Decrypt → 📁 Output File
```

#### **Hybrid Encryption Process:**
1. **สร้าง AES-256 key** แบบสุ่ม
2. **Encrypt ไฟล์** ด้วย AES-256-CBC 
3. **Encrypt AES key** ด้วย RSA-OAEP-256 ใน Azure Key Vault
4. **บันทึก** ข้อมูลที่เข้ารหัสเป็น JSON

**ข้อดี:** Private key ไม่เคยออกจาก Azure Key Vault HSM 🛡️

### 📋 **ข้อกำหนดเบื้องต้น**

#### **1. PowerShell Modules:**
```powershell
# ติดตั้ง Azure PowerShell modules
Install-Module Az.Accounts -Force -AllowClobber
Install-Module Az.KeyVault -Force -AllowClobber
```

#### **2. Azure Key Vault Setup:**
- ✅ RSA key ใน Azure Key Vault ชื่อ `nixkeydev001`
- ✅ Key type: **RSA** 
- ✅ Key size: **2048** หรือ **4096** bits
- ✅ Key operations: **Encrypt, Decrypt, Get**

#### **3. Service Principal:**
- ✅ Azure AD Service Principal
- ✅ สิทธิ์ **Key Vault Crypto User** 
- ✅ Client ID, Client Secret, Tenant ID

#### **4. Environment Variables:**
สร้างไฟล์ `.env` ใน folder เดียวกัน:
```env
CLIENT_ID="YOUR_AZURE_CLIENT_ID_HERE"
CLIENT_SECRET="YOUR_AZURE_CLIENT_SECRET_HERE"
TENANT_ID="YOUR_AZURE_TENANT_ID_HERE"
```

### 🚀 **การใช้งาน - Quick Start**

#### **📁 ไฟล์ที่มีอยู่:**
- `Encrypt-File.ps1` - Script สำหรับเข้ารหัสไฟล์
- `Decrypt-File.ps1` - Script สำหรับถอดรหัสไฟล์  
- `.env` - ไฟล์ environment variables
- `test.csv` - ไฟล์ตัวอย่างสำหรับทดสอบ

#### **🔒 Encrypt ไฟล์:**

```powershell
# วิธีง่ายสุด - encrypt test.csv
.\Encrypt-File.ps1

# Encrypt ไฟล์อื่น
.\Encrypt-File.ps1 -InputFile "document.pdf" -OutputFile "document.pdf.encrypted"

# Encrypt ไฟล์ ZIP
.\Encrypt-File.ps1 -InputFile "backup.zip" -OutputFile "backup.zip.encrypted"

# กำหนดพารามิเตอร์เต็ม
.\Encrypt-File.ps1 -InputFile "sensitive.xlsx" -OutputFile "sensitive.xlsx.encrypted" -KeyVaultUrl "https://nixakvdev002.vault.azure.net/" -KeyName "nixkeydev001"
```

#### **🔓 Decrypt ไฟล์:**

```powershell
# วิธีง่ายสุด - decrypt test.csv.encrypted
.\Decrypt-File.ps1

# Decrypt ไฟล์อื่น
.\Decrypt-File.ps1 -InputFile "document.pdf.encrypted" -OutputFile "document_restored.pdf"

# Decrypt ไฟล์ ZIP
.\Decrypt-File.ps1 -InputFile "backup.zip.encrypted" -OutputFile "backup_restored.zip"
```

### 🧪 **ขั้นตอนการทดสอบ**

#### **Test 1: ทดสอบไฟล์ CSV**
```powershell
# 1. Encrypt ไฟล์ CSV
.\Encrypt-File.ps1 -InputFile "test.csv" -OutputFile "test.csv.encrypted"

# 2. Decrypt กลับ
.\Decrypt-File.ps1 -InputFile "test.csv.encrypted" -OutputFile "test.csv.decrypted"

# 3. เปรียบเทียบไฟล์
Get-Content test.csv
Get-Content test.csv.decrypted
```

#### **Test 2: ทดสอบไฟล์ ZIP**
```powershell
# 1. สร้างไฟล์ ZIP
zip test-data.zip test.csv README.md

# 2. Encrypt ไฟล์ ZIP
.\Encrypt-File.ps1 -InputFile "test-data.zip" -OutputFile "test-data.zip.encrypted"

# 3. Decrypt กลับ
.\Decrypt-File.ps1 -InputFile "test-data.zip.encrypted" -OutputFile "test-data-restored.zip"

# 4. ทดสอบไฟล์ ZIP
unzip -t test-data-restored.zip
unzip -l test-data-restored.zip
```

#### **Test 3: ทดสอบไฟล์ขนาดใหญ่**
```powershell
# สร้างไฟล์ขนาดใหญ่ (1MB)
fsutil file createnew largefile.bin 1048576  # Windows
# หรือ
dd if=/dev/zero of=largefile.bin bs=1024 count=1024  # macOS/Linux

# Encrypt และ Decrypt
.\Encrypt-File.ps1 -InputFile "largefile.bin" -OutputFile "largefile.bin.encrypted"
.\Decrypt-File.ps1 -InputFile "largefile.bin.encrypted" -OutputFile "largefile.bin.decrypted"

# เปรียบเทียบ checksum
Get-FileHash largefile.bin
Get-FileHash largefile.bin.decrypted
```

### 📊 **ผลลัพธ์ที่คาดหวัง**
- ✅ ไฟล์ที่ decrypt แล้วต้องเหมือนไฟล์ต้นฉบับ 100%
- ✅ ไฟล์ ZIP สามารถ unzip ได้ปกติ
- ✅ Checksum ของไฟล์ต้นฉบับและไฟล์ที่ decrypt ต้องเหมือนกัน
- ✅ แสดงข้อความ "Encryption/Decryption Completed Successfully"

### 🔧 **โครงสร้างไฟล์ที่ Encrypt**

ไฟล์ที่ encrypt จะเป็น **JSON format**:

```json
{
  "EncryptedAESKey": "LVB1I6_cfa51OAD2_9wsMlWGq0x1W6nP9cCYmaHna1Y...",
  "IV": "dUu6EL0m9jw58uf1urTZYg==",
  "EncryptedContent": "PY76JJOLoIwSi2XP2PA4XFFVA/TZ/YFVMfA2NkLG/j6...",
  "Algorithm": "RSA-OAEP-256 + AES-256-CBC",
  "Timestamp": "2025-09-20 15:51:17 UTC"
}
```

#### **คำอธิบายฟิลด์:**
- **`EncryptedAESKey`**: AES key ที่เข้ารหัสด้วย RSA
- **`IV`**: Initialization Vector สำหรับ AES
- **`EncryptedContent`**: เนื้อหาไฟล์ที่เข้ารหัสด้วย AES
- **`Algorithm`**: Algorithm ที่ใช้
- **`Timestamp`**: เวลาที่เข้ารหัส

### 🛡️ **ความปลอดภัย**

| คุณสมบัติ | รายละเอียด |
|-----------|------------|
| 🔐 **Private Key** | ไม่เคยออกจาก Azure Key Vault HSM |
| 🔄 **Hybrid Encryption** | RSA + AES เพื่อประสิทธิภาพและความปลอดภัย |
| 👤 **Authentication** | Service Principal (ไม่ใช้ user credentials) |
| 🔑 **Key Management** | Azure Key Vault (Enterprise-grade) |
| 📊 **Compliance** | FIPS 140-3 Level 3 (Managed HSM) |

### ❌ **การแก้ไขปัญหา**

#### **🔍 ปัญหาที่พบบ่อย:**

| ปัญหา | สาเหตุ | วิธีแก้ |
|-------|--------|---------|
| **Authentication Failed** | Credentials ผิด | ตรวจสอบ `.env` file และสิทธิ์ Service Principal |
| **Key Not Found** | Key name ผิด | ตรวจสอบ key `nixkeydev001` ใน Key Vault |
| **Module Missing** | ไม่มี PowerShell modules | รัน `Install-Module` commands |
| **File Permission** | สิทธิ์ไฟล์ | Run PowerShell as Administrator |
| **Binary File Issue** | การอ่าน/เขียนไฟล์ผิด | ใช้ `-AsByteStream` parameter |

#### **🔧 คำสั่งแก้ไข:**

```powershell
# แก้ไข PowerShell Modules
Install-Module Az.Accounts -Force -AllowClobber
Install-Module Az.KeyVault -Force -AllowClobber

# ตรวจสอบ Authentication
Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId $TenantId

# ตรวจสอบ Key Vault Access
Get-AzKeyVaultKey -VaultName "nixakvdev002" -Name "nixkeydev001"

# Debug: แสดง environment variables
Get-ChildItem Env: | Where-Object {$_.Name -like "*CLIENT*" -or $_.Name -like "*TENANT*"}
```

### 💼 **Use Cases / กรณีการใช้งาน**

#### **📋 ตัวอย่างการใช้งานจริง:**

```powershell
# 🏢 Enterprise: Backup ข้อมูลสำคัญ
.\Encrypt-File.ps1 -InputFile "employee_data.xlsx" -OutputFile "employee_data.xlsx.encrypted"

# 📧 Email: ส่งไฟล์ sensitive
.\Encrypt-File.ps1 -InputFile "financial_report.pdf" -OutputFile "financial_report.pdf.encrypted"

# 💾 Archive: เก็บข้อมูลระยะยาว  
.\Encrypt-File.ps1 -InputFile "database_backup.zip" -OutputFile "database_backup.zip.encrypted"

# 🔄 การรับไฟล์: ผู้รับถอดรหัส
.\Decrypt-File.ps1 -InputFile "received_file.encrypted" -OutputFile "received_file.pdf"
```

#### **🎯 ข้อดีสำคัญ:**
- ✅ **ไฟล์ทุกประเภท**: CSV, PDF, ZIP, Excel, Images, Videos
- ✅ **ไฟล์ทุกขนาด**: จากไฟล์เล็ก KB ถึงใหญ่ GB
- ✅ **ความปลอดภัยสูง**: Enterprise-grade security
- ✅ **Central Key Management**: ควบคุมจาก Azure Key Vault
- ✅ **Audit Trail**: ติดตาม key usage ใน Azure
- ✅ **Cost Effective**: จ่ายตาม usage

### 🏗️ **Azure Key Vault Setup Commands**

```bash
# สร้าง Resource Group
az group create --name "myResourceGroup" --location "Southeast Asia"

# สร้าง Key Vault
az keyvault create --name "nixakvdev002" --resource-group "myResourceGroup" --location "Southeast Asia"

# สร้าง RSA Key (2048-bit)
az keyvault key create --vault-name "nixakvdev002" --name "nixkeydev001" --kty RSA --size 2048

# สร้าง Service Principal
az ad sp create-for-rbac --name "nixencryptdecryptapp001" --role contributor

# ให้สิทธิ์ Service Principal
az keyvault set-policy --name "nixakvdev002" --spn <CLIENT_ID> --key-permissions encrypt decrypt get list
```

### 📝 **หมายเหตุสำคัญ**

| เรื่อง | รายละเอียด |
|--------|------------|
| 🔐 **Algorithm** | RSA-OAEP-256 + AES-256-CBC (Hybrid) |
| 📁 **File Types** | รองรับไฟล์ทุกประเภท (Text, Binary) |
| 💾 **File Size** | ไม่จำกัดขนาด (ใช้ Hybrid Encryption) |
| 🏢 **Environment** | Production-ready สำหรับองค์กร |
| 🔑 **Key Security** | Private key ไม่เคยออกจาก Azure HSM |
| 💰 **Cost** | ประมาณ $0.03 ต่อ 10,000 operations |

#### **👨‍💻 Developer Notes**

- Scripts ใช้ **PowerShell Core** (Windows, macOS, Linux)
- รองรับ **binary files** ด้วย `-AsByteStream`
- ใช้ **Azure REST API** สำหรับ key operations
- **Error handling** และ **logging** ครบถ้วน
- **JSON output** format สำหรับ interoperability

---

## 🇺🇸 English {#english}

This project provides PowerShell scripts for **encrypting and decrypting all types of files** (CSV, ZIP, PDF, etc.) using **Azure Key Vault** with **RSA-OAEP-256 + AES-256-CBC** algorithms.

### 🎯 **Purpose**
- Encrypt sensitive files before sending or storing data
- Use Azure Key Vault as central key management
- Support files of any size (small or large)
- Enterprise-grade security

### 🏗️ **How It Works**
```
📁 Input File → 🔒 Encrypt → 📦 JSON File → 🔓 Decrypt → 📁 Output File
```

#### **Hybrid Encryption Process:**
1. **Generate random AES-256 key**
2. **Encrypt file** with AES-256-CBC 
3. **Encrypt AES key** with RSA-OAEP-256 in Azure Key Vault
4. **Save** encrypted data as JSON

**Benefit:** Private key never leaves Azure Key Vault HSM 🛡️

### 📋 **Prerequisites**

#### **1. PowerShell Modules:**
```powershell
# Install Azure PowerShell modules
Install-Module Az.Accounts -Force -AllowClobber
Install-Module Az.KeyVault -Force -AllowClobber
```

#### **2. Azure Key Vault Setup:**
- ✅ RSA key in Azure Key Vault named `nixkeydev001`
- ✅ Key type: **RSA** 
- ✅ Key size: **2048** or **4096** bits
- ✅ Key operations: **Encrypt, Decrypt, Get**

#### **3. Service Principal:**
- ✅ Azure AD Service Principal
- ✅ **Key Vault Crypto User** permissions
- ✅ Client ID, Client Secret, Tenant ID

#### **4. Environment Variables:**
Create `.env` file in the same folder:
```env
CLIENT_ID="YOUR_AZURE_CLIENT_ID_HERE"
CLIENT_SECRET="YOUR_AZURE_CLIENT_SECRET_HERE"
TENANT_ID="YOUR_AZURE_TENANT_ID_HERE"
```

### 🚀 **Usage - Quick Start**

#### **📁 Available Files:**
- `Encrypt-File.ps1` - Script for encrypting files
- `Decrypt-File.ps1` - Script for decrypting files  
- `.env` - Environment variables file
- `test.csv` - Sample file for testing

#### **🔒 Encrypt Files:**

```powershell
# Simplest way - encrypt test.csv
.\Encrypt-File.ps1

# Encrypt other files
.\Encrypt-File.ps1 -InputFile "document.pdf" -OutputFile "document.pdf.encrypted"

# Encrypt ZIP files
.\Encrypt-File.ps1 -InputFile "backup.zip" -OutputFile "backup.zip.encrypted"

# Full parameters
.\Encrypt-File.ps1 -InputFile "sensitive.xlsx" -OutputFile "sensitive.xlsx.encrypted" -KeyVaultUrl "https://nixakvdev002.vault.azure.net/" -KeyName "nixkeydev001"
```

#### **🔓 Decrypt Files:**

```powershell
# Simplest way - decrypt test.csv.encrypted
.\Decrypt-File.ps1

# Decrypt other files
.\Decrypt-File.ps1 -InputFile "document.pdf.encrypted" -OutputFile "document_restored.pdf"

# Decrypt ZIP files
.\Decrypt-File.ps1 -InputFile "backup.zip.encrypted" -OutputFile "backup_restored.zip"
```

### 🧪 **Testing Steps**

#### **Test 1: CSV Files**
```powershell
# 1. Encrypt CSV file
.\Encrypt-File.ps1 -InputFile "test.csv" -OutputFile "test.csv.encrypted"

# 2. Decrypt back
.\Decrypt-File.ps1 -InputFile "test.csv.encrypted" -OutputFile "test.csv.decrypted"

# 3. Compare files
Get-Content test.csv
Get-Content test.csv.decrypted
```

#### **Test 2: ZIP Files**
```powershell
# 1. Create ZIP file
zip test-data.zip test.csv README.md

# 2. Encrypt ZIP file
.\Encrypt-File.ps1 -InputFile "test-data.zip" -OutputFile "test-data.zip.encrypted"

# 3. Decrypt back
.\Decrypt-File.ps1 -InputFile "test-data.zip.encrypted" -OutputFile "test-data-restored.zip"

# 4. Test ZIP file
unzip -t test-data-restored.zip
unzip -l test-data-restored.zip
```

#### **Test 3: Large Files**
```powershell
# Create large file (1MB)
fsutil file createnew largefile.bin 1048576  # Windows
# or
dd if=/dev/zero of=largefile.bin bs=1024 count=1024  # macOS/Linux

# Encrypt and Decrypt
.\Encrypt-File.ps1 -InputFile "largefile.bin" -OutputFile "largefile.bin.encrypted"
.\Decrypt-File.ps1 -InputFile "largefile.bin.encrypted" -OutputFile "largefile.bin.decrypted"

# Compare checksum
Get-FileHash largefile.bin
Get-FileHash largefile.bin.decrypted
```

### 📊 **Expected Results**
- ✅ Decrypted files must be identical to original files (100%)
- ✅ ZIP files can be unzipped normally
- ✅ Checksums of original and decrypted files must match
- ✅ Display "Encryption/Decryption Completed Successfully" message

### 🔧 **Encrypted File Structure**

Encrypted files will be in **JSON format**:

```json
{
  "EncryptedAESKey": "LVB1I6_cfa51OAD2_9wsMlWGq0x1W6nP9cCYmaHna1Y...",
  "IV": "dUu6EL0m9jw58uf1urTZYg==",
  "EncryptedContent": "PY76JJOLoIwSi2XP2PA4XFFVA/TZ/YFVMfA2NkLG/j6...",
  "Algorithm": "RSA-OAEP-256 + AES-256-CBC",
  "Timestamp": "2025-09-20 15:51:17 UTC"
}
```

#### **Field Descriptions:**
- **`EncryptedAESKey`**: AES key encrypted with RSA
- **`IV`**: Initialization Vector for AES
- **`EncryptedContent`**: File content encrypted with AES
- **`Algorithm`**: Algorithm used
- **`Timestamp`**: Encryption time

### 🛡️ **Security**

| Feature | Details |
|---------|---------|
| 🔐 **Private Key** | Never leaves Azure Key Vault HSM |
| 🔄 **Hybrid Encryption** | RSA + AES for performance and security |
| 👤 **Authentication** | Service Principal (no user credentials) |
| 🔑 **Key Management** | Azure Key Vault (Enterprise-grade) |
| 📊 **Compliance** | FIPS 140-3 Level 3 (Managed HSM) |

### ❌ **Troubleshooting**

#### **🔍 Common Issues:**

| Issue | Cause | Solution |
|-------|-------|----------|
| **Authentication Failed** | Wrong credentials | Check `.env` file and Service Principal permissions |
| **Key Not Found** | Wrong key name | Check key `nixkeydev001` in Key Vault |
| **Module Missing** | Missing PowerShell modules | Run `Install-Module` commands |
| **File Permission** | File permissions | Run PowerShell as Administrator |
| **Binary File Issue** | Wrong file read/write | Use `-AsByteStream` parameter |

#### **🔧 Fix Commands:**

```powershell
# Fix PowerShell Modules
Install-Module Az.Accounts -Force -AllowClobber
Install-Module Az.KeyVault -Force -AllowClobber

# Check Authentication
Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId $TenantId

# Check Key Vault Access
Get-AzKeyVaultKey -VaultName "nixakvdev002" -Name "nixkeydev001"

# Debug: Show environment variables
Get-ChildItem Env: | Where-Object {$_.Name -like "*CLIENT*" -or $_.Name -like "*TENANT*"}
```

### 💼 **Use Cases**

#### **📋 Real-world Examples:**

```powershell
# 🏢 Enterprise: Backup critical data
.\Encrypt-File.ps1 -InputFile "employee_data.xlsx" -OutputFile "employee_data.xlsx.encrypted"

# 📧 Email: Send sensitive files
.\Encrypt-File.ps1 -InputFile "financial_report.pdf" -OutputFile "financial_report.pdf.encrypted"

# 💾 Archive: Long-term data storage
.\Encrypt-File.ps1 -InputFile "database_backup.zip" -OutputFile "database_backup.zip.encrypted"

# 🔄 File reception: Recipient decrypts
.\Decrypt-File.ps1 -InputFile "received_file.encrypted" -OutputFile "received_file.pdf"
```

#### **🎯 Key Benefits:**
- ✅ **All File Types**: CSV, PDF, ZIP, Excel, Images, Videos
- ✅ **Any File Size**: From small KB files to large GB files
- ✅ **High Security**: Enterprise-grade security
- ✅ **Central Key Management**: Controlled from Azure Key Vault
- ✅ **Audit Trail**: Track key usage in Azure
- ✅ **Cost Effective**: Pay per usage

### 🏗️ **Azure Key Vault Setup Commands**

```bash
# Create Resource Group
az group create --name "myResourceGroup" --location "Southeast Asia"

# Create Key Vault
az keyvault create --name "nixakvdev002" --resource-group "myResourceGroup" --location "Southeast Asia"

# Create RSA Key (2048-bit)
az keyvault key create --vault-name "nixakvdev002" --name "nixkeydev001" --kty RSA --size 2048

# Create Service Principal
az ad sp create-for-rbac --name "nixencryptdecryptapp001" --role contributor

# Grant Service Principal permissions
az keyvault set-policy --name "nixakvdev002" --spn <CLIENT_ID> --key-permissions encrypt decrypt get list
```

### 📝 **Important Notes**

| Topic | Details |
|-------|---------|
| 🔐 **Algorithm** | RSA-OAEP-256 + AES-256-CBC (Hybrid) |
| 📁 **File Types** | Supports all file types (Text, Binary) |
| 💾 **File Size** | No size limit (uses Hybrid Encryption) |
| 🏢 **Environment** | Production-ready for enterprises |
| 🔑 **Key Security** | Private key never leaves Azure HSM |
| 💰 **Cost** | Approximately $0.03 per 10,000 operations |

#### **👨‍💻 Developer Notes**

- Scripts use **PowerShell Core** (Windows, macOS, Linux)
- Support **binary files** with `-AsByteStream`
- Use **Azure REST API** for key operations
- Complete **error handling** and **logging**
- **JSON output** format for interoperability

**🎯 Ready for Production Use!** 🚀