# Windows PowerShell 5.1+; requests elevation only for protected registry keys.
# Policy names verified against brave-core v1.96.61 and Brave's policy docs.
[CmdletBinding()]
param(
    [ValidateSet('UI','Status','Library','VerifyUI')][string]$Mode = 'UI',
    [string]$ExpectedUserSid = '',
    [string]$PreviewPath = ''
)
$ErrorActionPreference = 'Stop'
if ($ExpectedUserSid -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ExpectedUserSid) {
    throw 'Elevation switched Windows accounts. Cancel and run using the original account; its Brave policies and backups must stay together.'
}
$script:PolicySubKey = 'Software\Policies\BraveSoftware\Brave'
$script:BackupDirectory = Join-Path $env:LOCALAPPDATA 'BraveFeatureControl'
$script:Features = @(
    [pscustomobject]@{Label='Leo AI'; Policy='BraveAIChatEnabled'; Off=0; Detail='Built-in AI assistant'}
    [pscustomobject]@{Label='Local AI'; Policy='BraveLocalAIEnabled'; Off=0; Detail='On-device AI, including semantic history search'}
    [pscustomobject]@{Label='Rewards / Brave Ads'; Policy='BraveRewardsDisabled'; Off=1; Detail='BAT rewards and associated ads'}
    [pscustomobject]@{Label='Wallet / Web3'; Policy='BraveWalletDisabled'; Off=1; Detail='Crypto wallet and decentralized DNS'}
    [pscustomobject]@{Label='Brave VPN'; Policy='BraveVPNDisabled'; Off=1; Detail='VPN integration; On does not purchase a subscription'}
    [pscustomobject]@{Label='Brave News'; Policy='BraveNewsDisabled'; Off=1; Detail='News feed and integration'}
    [pscustomobject]@{Label='Brave Talk'; Policy='BraveTalkDisabled'; Off=1; Detail='Video calling integration'}
    [pscustomobject]@{Label='Private windows with Tor'; Policy='TorDisabled'; Off=1; Detail='Optional Tor windows; separate from ordinary private windows'}
    [pscustomobject]@{Label='Playlist'; Policy='BravePlaylistEnabled'; Off=0; Detail='Media playlist; availability depends on the build'}
    [pscustomobject]@{Label='Speedreader'; Policy='BraveSpeedreaderEnabled'; Off=0; Detail='Simplified article reading'}
    [pscustomobject]@{Label='Wayback Machine'; Policy='BraveWaybackMachineEnabled'; Off=0; Detail='Archived-page suggestions for missing pages'}
    [pscustomobject]@{Label='Web Discovery'; Policy='BraveWebDiscoveryEnabled'; Off=0; Detail='Opt-in contributions to the Brave Search index'}
    [pscustomobject]@{Label='Product analytics (P3A)'; Policy='BraveP3AEnabled'; Off=0; Detail='Privacy-preserving product analytics'}
    [pscustomobject]@{Label='Daily usage ping'; Policy='BraveStatsPingEnabled'; Off=0; Detail='Usage statistics ping; browser updates stay enabled'}
    [pscustomobject]@{Label='Email aliases'; Policy='EmailAliasesEnabled'; Off=0; Detail='Built-in email alias integration; build dependent'}
)

function Test-PolicyWriteAccess {
    # Open the closest existing key with the exact write right we need.
    # This check never creates a key, changes permissions, or writes a value.
    $path = $script:PolicySubKey
    while ($path) {
        $existing = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path)
        if ($null -ne $existing) {
            $existing.Dispose()
            $rights = [System.Security.AccessControl.RegistryRights]::CreateSubKey
            if ($path -eq $script:PolicySubKey) { $rights = [System.Security.AccessControl.RegistryRights]::SetValue }
            try {
                $writable = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
                    $path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
                if ($null -eq $writable) { return $false }
                $writable.Dispose(); return $true
            } catch [System.Security.SecurityException] { return $false }
              catch [System.UnauthorizedAccessException] { return $false }
        }
        $separator = $path.LastIndexOf('\')
        if ($separator -lt 0) { return $false }
        $path = $path.Substring(0, $separator)
    }
    return $false
}
function Read-Policy([string]$Name, [switch]$Machine) {
    $hive = [Microsoft.Win32.Registry]::CurrentUser
    if ($Machine) { $hive = [Microsoft.Win32.Registry]::LocalMachine }
    $key = $hive.OpenSubKey($script:PolicySubKey)
    try {
        if ($null -eq $key -or $key.GetValueNames() -notcontains $Name) {
            return [pscustomobject]@{Exists=$false; Kind='DWord'; Value=$null}
        }
        return [pscustomobject]@{Exists=$true; Kind=$key.GetValueKind($Name).ToString(); Value=$key.GetValue($Name)}
    } finally { if ($null -ne $key) { $key.Dispose() } }
}
function Write-Policy([string]$Name, $State) {
    if ($script:Features.Policy -notcontains $Name) { throw "Unknown policy: $Name" }
    if ($State.Exists) {
        if ($State.Kind -ne 'DWord' -or [int]$State.Value -notin @(0,1)) { throw "Unsupported value for $Name" }
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PolicySubKey, $true)
        if ($null -eq $key) { $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($script:PolicySubKey) }
        try { $key.SetValue($Name, [int]$State.Value, [Microsoft.Win32.RegistryValueKind]::DWord) }
        finally { $key.Dispose() }
    } else {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($script:PolicySubKey, $true)
        if ($null -ne $key) { try { $key.DeleteValue($Name, $false) } finally { $key.Dispose() } }
    }
}
function Same-State($A, $B) {
    if ([bool]$A.Exists -ne [bool]$B.Exists) { return $false }
    if (-not $A.Exists) { return $true }
    return ($A.Kind -eq $B.Kind -and $A.Value -eq $B.Value)
}
function Load-Journal {
    $path = Join-Path $script:BackupDirectory 'restore.json'
    if (Test-Path -LiteralPath $path) {
        $journal = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($journal.Version -ne 1 -or $journal.PolicySubKey -ne $script:PolicySubKey) { throw 'Backup does not match this tool.' }
        foreach ($entry in $journal.Entries) {
            if ($script:Features.Policy -notcontains $entry.Name) { throw 'Backup contains an unknown policy.' }
            foreach ($state in @($entry.Original, $entry.Last)) {
                if ($state.Exists -and ($state.Kind -ne 'DWord' -or [int]$state.Value -notin @(0,1))) { throw 'Backup has an unsupported value.' }
            }
        }
        return $journal
    }
    return [pscustomobject]@{Version=1; PolicySubKey=$script:PolicySubKey; Entries=@()}
}
function Save-Journal($Journal) {
    New-Item -ItemType Directory -Path $script:BackupDirectory -Force | Out-Null
    $path = Join-Path $script:BackupDirectory 'restore.json'
    $temp = Join-Path $script:BackupDirectory 'restore.tmp'
    $Journal | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $path -Force
}
function Apply-Choices($Choices, [switch]$Restore) {
    # A named mutex prevents two copies from interleaving their backups/writes.
    $mutex = New-Object System.Threading.Mutex($false, 'Local\BraveFeatureControl')
    $held = $false
    try {
        try { $held = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another copy is applying changes. Try again shortly.' }
        $journal = Load-Journal
        $changes = @()
        $names = @($Choices.Keys)
        if ($Restore) { $names = @($journal.Entries | ForEach-Object { $_.Name }) }
        foreach ($name in $names) {
            $feature = $script:Features | Where-Object Policy -eq $name
            if ($null -eq $feature) { throw "Unknown policy: $name" }
            $before = Read-Policy $name
            if ($before.Exists -and ($before.Kind -ne 'DWord' -or [int]$before.Value -notin @(0,1))) { throw "Unsupported existing value for $name; left untouched." }
            $entry = @($journal.Entries | Where-Object Name -eq $name) | Select-Object -First 1
            if ($null -ne $entry -and -not (Same-State $before $entry.Last)) { throw "$name changed outside this tool. No changes applied; review the backup and brave://policy." }
            if ($Restore) { $after = $entry.Original }
            else {
                if ($Choices[$name] -notin @('Default','On','Off')) { throw "Invalid choice for $name" }
                $value = $feature.Off
                if ($Choices[$name] -eq 'On') { $value = 1 - $feature.Off }
                $after = [pscustomobject]@{Exists=($Choices[$name] -ne 'Default'); Kind='DWord'; Value=$value}
            }
            if (Same-State $before $after) { continue }
            if ((Read-Policy $name -Machine).Exists) { throw "$name is controlled by a machine policy. No changes applied." }
            $changes += [pscustomobject]@{Name=$name; Before=$before; After=$after}
            if (-not $Restore) {
                if ($null -eq $entry) {
                    $entry = [pscustomobject]@{Name=$name; Original=$before; Last=$after}
                    $journal.Entries = @($journal.Entries) + $entry
                } else { $entry.Last = $after }
            }
        }
        if ($changes.Count -eq 0) {
            # All tracked values were validated above, even when already original.
            if ($Restore -and @($journal.Entries).Count -gt 0) {
                $journal.Entries = @()
                Save-Journal $journal
            }
            return 'No changes needed.'
        }
        if (-not (Test-PolicyWriteAccess)) {
            throw 'Windows protects this policy key. Close this panel and reopen the updated launcher to request administrator access. No policies changed.'
        }
        New-Item -ItemType Directory -Path $script:BackupDirectory -Force | Out-Null
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-ffff'
        $snapshot = Join-Path $script:BackupDirectory "before-$stamp.json"
        $changes | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $snapshot -Encoding UTF8
        $previousJournal = Load-Journal
        # Persist recovery information before writing any policies.
        if (-not $Restore) { Save-Journal $journal }
        $written = @()
        try {
            foreach ($change in $changes) {
                $written += $change
                Write-Policy $change.Name $change.After
                if (-not (Same-State (Read-Policy $change.Name) $change.After)) { throw "Verification failed for $($change.Name)" }
            }
            if ($Restore) { $journal.Entries = @(); Save-Journal $journal }
        } catch {
            $failure = $_.Exception.Message
            $rollbackErrors = @()
            foreach ($change in $written) { try { Write-Policy $change.Name $change.Before } catch { $rollbackErrors += $_.Exception.Message } }
            if ($rollbackErrors.Count -eq 0) { Save-Journal $previousJournal; throw "Apply failed; previous values restored. $failure" }
            throw "Apply failed; rollback incomplete. Keep backup $snapshot. $failure $($rollbackErrors -join '; ')"
        }
        return "$($changes.Count) policies updated. Fully exit Brave and reopen it, then check brave://policy. Backup: $snapshot"
    } finally { if ($held) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}
function Get-Choice($Feature, $State) {
    if (-not $State.Exists) { return 'Default' }
    if ($State.Kind -ne 'DWord' -or [int]$State.Value -notin @(0,1)) { return 'Default' }
    if ([int]$State.Value -eq $Feature.Off) { return 'Off' }
    return 'On'
}
if ($Mode -eq 'Library') { return }
if ($Mode -eq 'Status') {
    $script:Features | ForEach-Object {
        [pscustomobject]@{Feature=$_.Label; UserPolicy=(Get-Choice $_ (Read-Policy $_.Policy)); MachinePolicy=(Get-Choice $_ (Read-Policy $_.Policy -Machine)); Policy=$_.Policy}
    } | Format-Table -AutoSize
    return
}
if ($Mode -eq 'UI' -and -not (Test-PolicyWriteAccess)) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The policy key remains protected even with administrator access. Its permissions were not changed.'
    }
    Write-Host 'Windows protects the Brave policy key. Requesting administrator access for this panel.'
    $arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Mode UI -ExpectedUserSid "' + $identity.User.Value + '"'
    try { Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden | Out-Null }
    catch { throw 'Administrator launch was cancelled or denied. No policies were changed. Reopen the launcher when ready.' }
    return
}
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 Title="Brave Feature Control" Width="1040" Height="830" MinWidth="850" MinHeight="650" WindowStartupLocation="CenterScreen"
 Background="#F6F5F2" FontFamily="Segoe UI" Foreground="#242628" FontSize="14">
 <Window.Resources>
  <Style TargetType="Button">
   <Setter Property="Background" Value="White"/><Setter Property="Foreground" Value="#343638"/>
   <Setter Property="BorderBrush" Value="#DEDFDA"/><Setter Property="BorderThickness" Value="1"/>
   <Setter Property="Padding" Value="18,11"/><Setter Property="Cursor" Value="Hand"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
    <Border x:Name="Shell" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="9">
     <ContentPresenter Margin="{TemplateBinding Padding}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border><ControlTemplate.Triggers>
     <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Shell" Property="Opacity" Value="0.8"/></Trigger>
     <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Shell" Property="BorderBrush" Value="#DA491F"/></Trigger>
     <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Shell" Property="Opacity" Value="0.4"/></Trigger>
    </ControlTemplate.Triggers>
   </ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style TargetType="RadioButton">
   <Setter Property="Cursor" Value="Hand"/><Setter Property="Foreground" Value="#727675"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="RadioButton">
    <Border x:Name="Pill" Background="Transparent" CornerRadius="6" Padding="12,8" Margin="2">
     <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
    </Border><ControlTemplate.Triggers>
     <Trigger Property="IsChecked" Value="True"><Setter TargetName="Pill" Property="Background" Value="#FFFFFF"/><Setter Property="Foreground" Value="#C13D18"/><Setter Property="FontWeight" Value="SemiBold"/></Trigger>
     <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Pill" Property="Background" Value="#F9F9F7"/></Trigger>
     <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="Pill" Property="BorderBrush" Value="#DA491F"/><Setter TargetName="Pill" Property="BorderThickness" Value="1"/></Trigger>
     <Trigger Property="IsEnabled" Value="False"><Setter TargetName="Pill" Property="Opacity" Value="0.45"/></Trigger>
    </ControlTemplate.Triggers>
   </ControlTemplate></Setter.Value></Setter>
  </Style>
 </Window.Resources>
 <Grid Margin="28,24,28,22">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <Grid Grid.Row="0" Margin="0,0,0,24">
   <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
   <StackPanel>
    <TextBlock Text="BRAVE / FEATURE CONTROL" Foreground="#B64424" FontSize="11" FontWeight="Bold" Margin="0,0,0,8"/>
    <TextBlock Text="Less clutter. Your choice." FontSize="30" FontWeight="SemiBold"/>
    <TextBlock Text="Keep the features you use. Switch off the rest." Foreground="#747877" Margin="0,8,0,0"/>
   </StackPanel>
   <Border Grid.Column="1" Background="#EAEDE6" CornerRadius="14" VerticalAlignment="Top" Padding="12,6" Margin="20,7,0,0">
    <TextBlock Text="LOCAL CONTROLS" FontSize="10" FontWeight="SemiBold" Foreground="#58644C"/>
   </Border>
  </Grid>
  <Border Grid.Row="1" Background="White" BorderBrush="#E4E4DF" BorderThickness="1" CornerRadius="12" Padding="18,15" Margin="0,0,0,18">
   <Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <StackPanel VerticalAlignment="Center" Margin="0,0,14,0">
     <TextBlock Text="Start with a clean slate" FontWeight="SemiBold" FontSize="15"/>
     <TextBlock Text="Minimal stages every optional feature Off. Adjust before applying." Foreground="#777B78" FontSize="12" TextWrapping="Wrap" Margin="0,5,0,0"/>
    </StackPanel>
    <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
     <Button x:Name="DefaultButton" Content="All Default" Margin="0,0,10,0"/>
     <Button x:Name="MinimalButton" Content="Minimal preset" Background="#FDECE5" Foreground="#B33C1E" BorderBrush="#F4D8CA" FontWeight="SemiBold"/>
    </StackPanel>
   </Grid>
  </Border>
  <Grid Grid.Row="2">
   <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
   <Grid Margin="2,0,2,12"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <TextBlock x:Name="CountLabel" Foreground="#686D69" FontSize="12" VerticalAlignment="Center"/>
    <TextBlock Grid.Column="1" Text="Default = Brave settings  /  On = available  /  Off = disabled" Foreground="#777B78" FontSize="11" VerticalAlignment="Center"/>
   </Grid>
   <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="0,0,8,0">
    <StackPanel x:Name="FeatureList"/>
   </ScrollViewer>
  </Grid>
  <Border Grid.Row="3" Background="#EDEEE9" CornerRadius="9" Padding="13,10" Margin="0,16,0,14">
   <TextBlock x:Name="StatusLabel" Text="Ready. Changes are saved only when you click Apply." Foreground="#586159" TextWrapping="Wrap" FontSize="12"/>
  </Border>
  <Grid Grid.Row="4"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
   <StackPanel><StackPanel Orientation="Horizontal" Margin="0,0,0,8">
    <Button x:Name="RestoreButton" Content="Restore original" Padding="12,8" FontSize="12" Margin="0,0,8,0"/>
    <Button x:Name="ReloadButton" Content="Reload" Padding="12,8" FontSize="12" Margin="0,0,8,0"/>
    <Button x:Name="BackupButton" Content="Backups" Padding="12,8" FontSize="12"/>
   </StackPanel>
   <TextBlock Text="All profiles for this Windows user. Policies may show 'Managed by your organization'." FontSize="10" Foreground="#7B807C" TextWrapping="Wrap" Margin="0,0,16,0"/>
   </StackPanel>
   <Button x:Name="ApplyButton" Grid.Column="1" Content="Apply changes" Background="#DA491F" Foreground="White" BorderBrush="#DA491F" FontWeight="SemiBold" Padding="26,13" VerticalAlignment="Top"/>
  </Grid>
 </Grid>
</Window>
'@
$reader = New-Object System.Xml.XmlNodeReader($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$list = $window.FindName('FeatureList')
$status = $window.FindName('StatusLabel')
$countLabel = $window.FindName('CountLabel')
$script:Controls = @{}
$script:LoadedChoices = @{}
function Update-Summary {
    $off = 0; $pending = 0
    foreach ($name in $script:Controls.Keys) {
        $control = $script:Controls[$name]
        $choice = @($control.Buttons | Where-Object IsChecked | ForEach-Object { $_.Content })[0]
        if ($choice -eq 'Off') { $off++ }
        if ($choice -ne $script:LoadedChoices[$name]) { $pending++ }
    }
    $countLabel.Text = "$off of $($script:Features.Count) set to Off   |   $pending pending changes"
    $window.FindName('ApplyButton').IsEnabled = ($pending -gt 0)
}
function Refresh-Cards {
    $list.Children.Clear(); $script:Controls = @{}; $script:LoadedChoices = @{}
    $groups = @(
        @{Title='AI & ASSISTANTS'; Names=@('BraveAIChatEnabled','BraveLocalAIEnabled')}
        @{Title='REWARDS & SERVICES'; Names=@('BraveRewardsDisabled','BraveWalletDisabled','BraveVPNDisabled','BraveTalkDisabled','EmailAliasesEnabled')}
        @{Title='READING & BROWSING'; Names=@('BraveNewsDisabled','BravePlaylistEnabled','BraveSpeedreaderEnabled','BraveWaybackMachineEnabled','TorDisabled')}
        @{Title='ANALYTICS & CONTRIBUTIONS'; Names=@('BraveWebDiscoveryEnabled','BraveP3AEnabled','BraveStatsPingEnabled')}
    )
    foreach ($group in $groups) {
        $heading = New-Object Windows.Controls.TextBlock
        $heading.Text = $group.Title; $heading.FontSize = 10; $heading.FontWeight = 'SemiBold'
        $heading.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#747B72')
        $heading.Margin = '3,12,0,9'; [void]$list.Children.Add($heading)
        foreach ($name in $group.Names) {
            $feature = $script:Features | Where-Object Policy -eq $name
            $state = Read-Policy $name; $machine = Read-Policy $name -Machine
            $choice = Get-Choice $feature $state
            $script:LoadedChoices[$name] = $choice
            $locked = $machine.Exists -or ($state.Exists -and ($state.Kind -ne 'DWord' -or [int]$state.Value -notin @(0,1)))
            $card = New-Object Windows.Controls.Border
            $card.Background = [Windows.Media.Brushes]::White; $card.CornerRadius = '10'
            $card.BorderBrush = [Windows.Media.BrushConverter]::new().ConvertFromString('#E5E6E0')
            $card.BorderThickness = '1'; $card.Padding = '17,13'; $card.Margin = '0,0,0,7'
            $row = New-Object Windows.Controls.Grid
            $column = New-Object Windows.Controls.ColumnDefinition; $column.Width = '*'; [void]$row.ColumnDefinitions.Add($column)
            $column = New-Object Windows.Controls.ColumnDefinition; $column.Width = 'Auto'; [void]$row.ColumnDefinitions.Add($column)
            $text = New-Object Windows.Controls.StackPanel; $text.Margin = '0,0,18,0'; $text.VerticalAlignment = 'Center'
            $label = New-Object Windows.Controls.TextBlock
            $label.Text = $feature.Label; $label.FontSize = 14; $label.FontWeight = 'SemiBold'; $label.ToolTip = $name
            [void]$text.Children.Add($label)
            $detail = New-Object Windows.Controls.TextBlock
            $detail.Text = $feature.Detail; $detail.FontSize = 11; $detail.Margin = '0,4,0,0'; $detail.TextWrapping = 'Wrap'
            $detail.Foreground = [Windows.Media.BrushConverter]::new().ConvertFromString('#797F79')
            if ($locked) { $detail.Text = 'Locked by machine policy or an unsupported value. Check brave://policy.' }
            [void]$text.Children.Add($detail); [void]$row.Children.Add($text)
            $selector = New-Object Windows.Controls.Border
            $selector.Background = [Windows.Media.BrushConverter]::new().ConvertFromString('#EEEFEA')
            $selector.CornerRadius = '8'; $selector.Padding = '2'; $selector.VerticalAlignment = 'Center'
            [Windows.Controls.Grid]::SetColumn($selector, 1)
            $segments = New-Object Windows.Controls.StackPanel; $segments.Orientation = 'Horizontal'
            $buttons = @()
            foreach ($option in @('Default','On','Off')) {
                $button = New-Object Windows.Controls.RadioButton
                $button.Content = $option; $button.GroupName = $name; $button.IsChecked = ($choice -eq $option); $button.IsEnabled = -not $locked
                $button.ToolTip = "$($feature.Label): $option"
                [Windows.Automation.AutomationProperties]::SetName($button, "$($feature.Label): $option")
                $button.Add_Checked({ Update-Summary })
                [void]$segments.Children.Add($button); $buttons += $button
            }
            $selector.Child = $segments; [void]$row.Children.Add($selector)
            $card.Child = $row; [void]$list.Children.Add($card)
            $script:Controls[$name] = [pscustomobject]@{Buttons=$buttons; Locked=$locked}
        }
    }
    Update-Summary
}
function Show-Failure($ErrorRecord) {
    $status.Text = $ErrorRecord.Exception.Message
    [Windows.MessageBox]::Show($window, $status.Text, 'Brave Feature Control', 'OK', 'Error') | Out-Null
}
$window.FindName('MinimalButton').Add_Click({
    foreach ($control in $script:Controls.Values) { if (-not $control.Locked) { ($control.Buttons | Where-Object Content -eq 'Off').IsChecked = $true } }
    $status.Text = 'Minimal preset staged, including Tor and Speedreader. Keep anything you use On, then Apply.'
})
$window.FindName('DefaultButton').Add_Click({
    foreach ($control in $script:Controls.Values) { if (-not $control.Locked) { ($control.Buttons | Where-Object Content -eq 'Default').IsChecked = $true } }
    $status.Text = 'Default staged. Brave settings will decide which features are enabled after Apply.'
})
$window.FindName('ApplyButton').Add_Click({
    try {
        $choices = @{}
        foreach ($name in $script:Controls.Keys) {
            $control = $script:Controls[$name]
            $choice = [string](@($control.Buttons | Where-Object IsChecked | ForEach-Object { $_.Content })[0])
            if (-not $control.Locked -and $choice -ne $script:LoadedChoices[$name]) { $choices[$name] = $choice }
        }
        $result = Apply-Choices $choices; Refresh-Cards; $status.Text = $result
    } catch { Show-Failure $_ }
})
$window.FindName('RestoreButton').Add_Click({
    try { $result = Apply-Choices @{} -Restore; Refresh-Cards; $status.Text = $result } catch { Show-Failure $_ }
})
$window.FindName('ReloadButton').Add_Click({
    try { Refresh-Cards; $status.Text = 'Policy values reloaded. Unapplied choices discarded.' } catch { Show-Failure $_ }
})
$window.FindName('BackupButton').Add_Click({
    try { New-Item -ItemType Directory -Path $script:BackupDirectory -Force | Out-Null; Start-Process explorer.exe -ArgumentList ('"' + $script:BackupDirectory + '"') } catch { Show-Failure $_ }
})
Refresh-Cards
if ($Mode -eq 'VerifyUI') {
    if ($script:Controls.Count -ne $script:Features.Count) { throw 'UI card count mismatch.' }
    $window.FindName('MinimalButton').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    foreach ($control in $script:Controls.Values) {
        if (-not $control.Locked -and -not ($control.Buttons | Where-Object Content -eq 'Off').IsChecked) { throw 'Preset failed.' }
    }
    $window.FindName('DefaultButton').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    foreach ($control in $script:Controls.Values) {
        if (-not $control.Locked -and -not ($control.Buttons | Where-Object Content -eq 'Default').IsChecked) { throw 'Default preset failed.' }
    }
    $window.FindName('MinimalButton').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
    if ($PreviewPath) {
        $preview = New-Object Windows.Controls.Border
        $preview.Background = $window.Background; $preview.Resources = $window.Resources
        $content = $window.Content; $window.Content = $null; $preview.Child = $content
        $preview.Measure([Windows.Size]::new(1040,830)); $preview.Arrange([Windows.Rect]::new(0,0,1040,830)); $preview.UpdateLayout()
        $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new(1040,830,96,96,[Windows.Media.PixelFormats]::Pbgra32)
        $bitmap.Render($preview)
        $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
        $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
        $stream = [IO.File]::Create([IO.Path]::GetFullPath($PreviewPath))
        try { $encoder.Save($stream) } finally { $stream.Dispose() }
    }
    $window.Close(); Write-Output 'WPF UI and preset verified; no policies changed.'; return
}
[void]$window.ShowDialog()
