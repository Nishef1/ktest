param(
    [string]$Repository = "Nishef1/ktest",
    [string]$SigningDirectory = (Join-Path $env:LOCALAPPDATA "KTest\preview-signing")
)
$ErrorActionPreference = "Stop"
# This is a preview-app signer, not the MITM CA and not a production release key.
# Keep its backup private. The local password uses Windows user-bound DPAPI.
if ($Repository -ne "Nishef1/ktest") { throw "Unexpected signing repository" }
$keytool = Join-Path $env:ProgramFiles "Android\Android Studio\jbr\bin\keytool.exe"
if (-not (Test-Path -LiteralPath $keytool)) { throw "Android Studio keytool is required" }
$signingPath = [IO.Path]::GetFullPath($SigningDirectory)
New-Item -ItemType Directory -Path $signingPath -Force | Out-Null
$keystore = Join-Path $signingPath "ktest-preview.p12"
$credentials = Join-Path $signingPath "password.xml"
$certificate = Join-Path $signingPath "certificate.der"
$alias = "ktest-preview"
if ((Test-Path -LiteralPath $keystore) -ne (Test-Path -LiteralPath $credentials)) {
    throw "Incomplete signing backup; refusing to replace an existing key"
}
if (Test-Path -LiteralPath $credentials) {
    $secret = Import-Clixml -LiteralPath $credentials
} else {
    $bytes = [byte[]]::new(48)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $secret = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
    $secret | Export-Clixml -LiteralPath $credentials
}
$password = [Net.NetworkCredential]::new("", $secret).Password
function Invoke-PrivateTool([string]$Executable, [string[]]$Arguments, [string]$InputText = "") {
    $start = [Diagnostics.ProcessStartInfo]::new($Executable)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.Environment["KTEST_SIGN_PASSWORD"] = $password
    $process = [Diagnostics.Process]::Start($start)
    if ($InputText.Length -gt 0) { $process.StandardInput.Write($InputText) }
    $process.StandardInput.Close()
    $outputTask = $process.StandardOutput.ReadToEndAsync()
    $errorTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $null = $outputTask.Result
    $null = $errorTask.Result
    if ($process.ExitCode -ne 0) { throw "Signing tool failed ($Executable, exit $($process.ExitCode)); private output suppressed" }
    $process.Dispose()
}
try {
    if (-not (Test-Path -LiteralPath $keystore)) {
        Invoke-PrivateTool $keytool @("-genkeypair", "-keystore", $keystore, "-storetype", "PKCS12",
            "-storepass:env", "KTEST_SIGN_PASSWORD", "-keypass:env", "KTEST_SIGN_PASSWORD",
            "-alias", $alias, "-keyalg", "RSA", "-keysize", "3072", "-validity", "10000",
            "-dname", "CN=KTest Preview, OU=Internal Validation, O=KTest", "-noprompt")
    }
    Invoke-PrivateTool $keytool @("-exportcert", "-keystore", $keystore, "-storepass:env", "KTEST_SIGN_PASSWORD",
        "-alias", $alias, "-file", $certificate)
    $fingerprint = (Get-FileHash -LiteralPath $certificate -Algorithm SHA256).Hash.ToLowerInvariant()
    $gh = (Get-Command gh -ErrorAction Stop).Source
    $values = @{
        KTEST_PREVIEW_KEYSTORE_BASE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($keystore))
        KTEST_PREVIEW_KEYSTORE_PASSWORD = $password
        KTEST_PREVIEW_KEY_ALIAS = $alias
        KTEST_PREVIEW_KEY_PASSWORD = $password
        KTEST_PREVIEW_CERT_SHA256 = $fingerprint
    }
    foreach ($name in $values.Keys) {
        Invoke-PrivateTool $gh @("secret", "set", $name, "--repo", $Repository) $values[$name]
    }
    Write-Output "Stable preview signing configured for $Repository"
    Write-Output "Public certificate SHA-256: $fingerprint"
    Write-Output "Private local backup: $signingPath (do not delete or commit)"
} finally {
    $password = $null
    $values = $null
}
