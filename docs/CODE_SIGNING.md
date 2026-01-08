# Code Signing Guide for Skidrow Killer

This document explains how to set up code signing for distributing Skidrow Killer as a trusted application.

## Why Code Signing?

Code signing is essential for production distribution because:
- Windows SmartScreen won't block signed applications
- Users will trust the application more
- Prevents tampering with the executable
- Required for enterprise deployment

## Prerequisites

1. **Code Signing Certificate**
   - Purchase from a trusted CA (Comodo, DigiCert, Sectigo, etc.)
   - Or use a self-signed certificate for internal distribution

2. **Windows SDK**
   - Install Windows SDK for `signtool.exe`
   - Add to PATH: `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\`

## Setting Up Code Signing

### Option 1: Using PowerShell Build Script

```powershell
# Sign with certificate file
.\build-release.ps1 -SignCode -CertificatePath "path\to\certificate.pfx" -CertificatePassword (ConvertTo-SecureString "password" -AsPlainText -Force) -CreateZip

# Sign with certificate from Windows Certificate Store
# (Modify the script to use /sha1 parameter instead of /f)
```

### Option 2: Manual Signing

```batch
REM Sign with PFX file
signtool sign /f "certificate.pfx" /p "password" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "SkidrowKiller.exe"

REM Sign with certificate from store
signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "SkidrowKiller.exe"

REM Verify signature
signtool verify /pa "SkidrowKiller.exe"
```

### Option 3: Azure Key Vault Signing (Recommended for CI/CD)

```powershell
# Install AzureSignTool
dotnet tool install --global AzureSignTool

# Sign using Azure Key Vault
AzureSignTool sign -kvu "https://your-vault.vault.azure.net" `
    -kvi "client-id" `
    -kvs "client-secret" `
    -kvc "certificate-name" `
    -tr http://timestamp.digicert.com `
    -td sha256 `
    "bin\Publish\win-x64-portable\SkidrowKiller.exe"
```

## GitHub Actions CI/CD

Add this to your `.github/workflows/release.yml`:

```yaml
name: Build and Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: windows-latest

    steps:
    - uses: actions/checkout@v4

    - name: Setup .NET
      uses: actions/setup-dotnet@v4
      with:
        dotnet-version: '8.0.x'

    - name: Restore dependencies
      run: dotnet restore

    - name: Build
      run: dotnet build -c Release --no-restore

    - name: Publish x64 Portable
      run: |
        dotnet publish -c Release -r win-x64 --self-contained true `
          /p:PublishSingleFile=true `
          /p:PublishReadyToRun=true `
          /p:EnableCompressionInSingleFile=true `
          -o publish/win-x64-portable

    - name: Sign Executable
      if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')
      env:
        AZURE_KEY_VAULT_URI: ${{ secrets.AZURE_KEY_VAULT_URI }}
        AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
        AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
        AZURE_CERT_NAME: ${{ secrets.AZURE_CERT_NAME }}
      run: |
        dotnet tool install --global AzureSignTool
        AzureSignTool sign -kvu "$env:AZURE_KEY_VAULT_URI" `
          -kvi "$env:AZURE_CLIENT_ID" `
          -kvs "$env:AZURE_CLIENT_SECRET" `
          -kvc "$env:AZURE_CERT_NAME" `
          -tr http://timestamp.digicert.com `
          -td sha256 `
          "publish/win-x64-portable/SkidrowKiller.exe"

    - name: Create Release
      uses: softprops/action-gh-release@v1
      if: startsWith(github.ref, 'refs/tags/')
      with:
        files: |
          publish/win-x64-portable/SkidrowKiller.exe
```

## Creating a Self-Signed Certificate (For Testing)

```powershell
# Create self-signed certificate (PowerShell Admin)
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=Skidrow Killer Development, O=xman studio" `
    -KeyUsage DigitalSignature `
    -FriendlyName "Skidrow Killer Dev Cert" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(3)

# Export to PFX
$password = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "SkidrowKiller-dev.pfx" -Password $password

# Trust the certificate (for testing only)
Import-Certificate -FilePath "SkidrowKiller-dev.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
```

## Timestamp Servers

Always use a timestamp server to ensure signatures remain valid after certificate expiration:

- DigiCert: `http://timestamp.digicert.com`
- Comodo: `http://timestamp.comodoca.com`
- Sectigo: `http://timestamp.sectigo.com`
- GlobalSign: `http://timestamp.globalsign.com/scripts/timestamp.dll`

## Verification

After signing, verify the signature:

```batch
REM Check signature
signtool verify /pa /v "SkidrowKiller.exe"

REM Check certificate chain
signtool verify /pa /all /v "SkidrowKiller.exe"
```

## Troubleshooting

### "A certificate chain could not be built"
- Ensure the root CA is trusted
- Check intermediate certificates

### "The signature is invalid"
- File may have been modified after signing
- Re-sign the file

### SmartScreen still blocks the app
- Use an EV (Extended Validation) certificate
- Build reputation over time with a standard certificate
- Submit to Microsoft for analysis

## Best Practices

1. **Never commit certificates to source control**
2. **Use environment variables or secrets management**
3. **Always use timestamps**
4. **Use SHA-256 or higher for digest algorithm**
5. **Consider EV certificates for better SmartScreen reputation**
6. **Rotate certificates before expiration**
