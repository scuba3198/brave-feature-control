$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\Brave-Feature-Control.ps1" -Mode Library
$script:PolicySubKey = 'Software\CodexBraveFeatureControlTest\' + [guid]::NewGuid().ToString('N')
$script:BackupDirectory = Join-Path $PSScriptRoot ('test-backups-' + [guid]::NewGuid().ToString('N'))
function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    Assert ($script:Features.Count -eq 15) 'Expected 15 features'
    foreach ($feature in $script:Features) {
        $choices = @{}; $choices[$feature.Policy] = 'Off'
        Apply-Choices $choices | Out-Null
        Assert ((Read-Policy $feature.Policy).Value -eq $feature.Off) "Off polarity: $($feature.Policy)"
        $choices[$feature.Policy] = 'On'; Apply-Choices $choices | Out-Null
        Assert ((Read-Policy $feature.Policy).Value -eq (1 - $feature.Off)) "On polarity: $($feature.Policy)"
    }
    Apply-Choices @{} -Restore | Out-Null
    foreach ($feature in $script:Features) { Assert (-not (Read-Policy $feature.Policy).Exists) 'Restore absent value' }
    # Returning to an absent original through Default must end tracking on Restore.
    Apply-Choices @{BraveAIChatEnabled='Off'} | Out-Null
    Apply-Choices @{BraveAIChatEnabled='Default'} | Out-Null
    $snapshotsBefore = @(Get-ChildItem -LiteralPath $script:BackupDirectory -Filter 'before-*.json').Count
    Apply-Choices @{} -Restore | Out-Null
    Assert (@((Load-Journal).Entries).Count -eq 0) 'No-op restore clears absent original tracking'
    Assert (-not (Read-Policy 'BraveAIChatEnabled').Exists) 'No-op restore preserves absent original'
    Assert (@(Get-ChildItem -LiteralPath $script:BackupDirectory -Filter 'before-*.json').Count -eq $snapshotsBefore) 'No-op restore needs no policy snapshot'
    # A later externally set value is a fresh original, not a stale conflict.
    Write-Policy 'BraveAIChatEnabled' ([pscustomobject]@{Exists=$true; Kind='DWord'; Value=1})
    Apply-Choices @{BraveAIChatEnabled='Off'} | Out-Null
    Apply-Choices @{BraveAIChatEnabled='On'} | Out-Null
    Apply-Choices @{} -Restore | Out-Null
    Assert (@((Load-Journal).Entries).Count -eq 0) 'No-op restore clears pre-existing original tracking'
    Assert ((Read-Policy 'BraveAIChatEnabled').Value -eq 1) 'No-op restore preserves pre-existing original'
    Write-Policy 'BraveAIChatEnabled' ([pscustomobject]@{Exists=$true; Kind='DWord'; Value=0})
    Apply-Choices @{BraveAIChatEnabled='On'} | Out-Null
    Apply-Choices @{} -Restore | Out-Null
    Assert ((Read-Policy 'BraveAIChatEnabled').Value -eq 0) 'Fresh apply captures new original after no-op restore'
    Write-Policy 'BraveAIChatEnabled' ([pscustomobject]@{Exists=$true; Kind='DWord'; Value=1})
    Apply-Choices @{BraveAIChatEnabled='Off'} | Out-Null
    Apply-Choices @{BraveAIChatEnabled='Default'} | Out-Null
    Assert (-not (Read-Policy 'BraveAIChatEnabled').Exists) 'Default removes user policy'
    Apply-Choices @{} -Restore | Out-Null
    Assert ((Read-Policy 'BraveAIChatEnabled').Value -eq 1) 'Restore pre-existing policy'
    Apply-Choices @{BraveAIChatEnabled='Off'} | Out-Null
    Write-Policy 'BraveAIChatEnabled' ([pscustomobject]@{Exists=$true; Kind='DWord'; Value=1})
    $blocked = $false
    try { Apply-Choices @{BraveAIChatEnabled='Default'; BraveRewardsDisabled='Off'} | Out-Null } catch { $blocked = $_.Exception.Message -like '*outside this tool*' }
    Assert $blocked 'Detect external change'
    Assert (-not (Read-Policy 'BraveRewardsDisabled').Exists) 'Conflict preflight prevents partial writes'
    $blocked = $false
    try { Apply-Choices @{} -Restore | Out-Null } catch { $blocked = $_.Exception.Message -like '*outside this tool*' }
    Assert $blocked 'Restore still detects external change'
    Assert (@((Load-Journal).Entries).Count -eq 1) 'Conflicting restore preserves journal'
    Write-Policy 'BraveAIChatEnabled' ([pscustomobject]@{Exists=$true; Kind='DWord'; Value=0})
    Apply-Choices @{} -Restore | Out-Null
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PolicySubKey, $true)
    try { $key.SetValue('UnrelatedSetting', 'keep', [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
    Apply-Choices @{BraveRewardsDisabled='Off'} | Out-Null
    Apply-Choices @{} -Restore | Out-Null
    Assert ((Read-Policy 'UnrelatedSetting').Value -eq 'keep') 'Unrelated values preserved'
    # Simulate a registry-write failure on the second write; verify rollback.
    $originalWriter = ${function:Write-Policy}
    $script:TestWriteCount = 0
    function Write-Policy([string]$Name, $State) {
        $script:TestWriteCount++
        if ($script:TestWriteCount -eq 2) { throw 'Simulated write failure' }
        & $originalWriter $Name $State
    }
    $blocked = $false
    try { Apply-Choices @{BraveRewardsDisabled='Off'; BraveWalletDisabled='Off'} | Out-Null } catch { $blocked = $_.Exception.Message -like '*previous values restored*' }
    Assert $blocked 'Rollback reported'
    Assert (-not (Read-Policy 'BraveRewardsDisabled').Exists) 'Rollback rewards'
    Assert (-not (Read-Policy 'BraveWalletDisabled').Exists) 'Rollback wallet'
    Assert (@((Load-Journal).Entries).Count -eq 0) 'Rollback journal'
    function Test-PolicyWriteAccess { return $false }
    $blocked = $false
    try { Apply-Choices @{BraveRewardsDisabled='Off'} | Out-Null } catch { $blocked = $_.Exception.Message -like '*Windows protects*' }
    Assert $blocked 'Protected registry preflight'
    Assert (-not (Read-Policy 'BraveRewardsDisabled').Exists) 'Permission denial preserves policies'
    Assert (@((Load-Journal).Entries).Count -eq 0) 'Permission denial preserves restore journal'
    Write-Output 'PASS: 15 on/off mappings, defaults, restore (including no-op journal cleanup), conflicts, unrelated values, rollback, and protected-key preflight.'
} finally {
    if ($script:PolicySubKey -notlike 'Software\CodexBraveFeatureControlTest\*') { throw 'Unsafe test cleanup path' }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($script:PolicySubKey, $false)
    $resolved = [IO.Path]::GetFullPath($script:BackupDirectory)
    $allowed = [IO.Path]::GetFullPath($PSScriptRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test file cleanup path' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
