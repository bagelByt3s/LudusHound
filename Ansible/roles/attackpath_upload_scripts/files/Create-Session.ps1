# Script to create scheduled tasks for users with sessions on this computer
# Save as: Create-UserSessions.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$AttackPath
)

# Set up logging
$logDir = "C:\Windows\Tasks\LudusHound\AttackPath\Logs"
$logFileName = "CreateSession_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logPath = Join-Path -Path $logDir -ChildPath $logFileName

# Ensure log directory exists
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Start transcript logging
Start-Transcript -Path $logPath -Append

Write-Host "Script execution started at $(Get-Date)" -ForegroundColor Cyan
Write-Host "Attack Path: $AttackPath" -ForegroundColor Cyan

# Get current computer information
$CurrentComputer = $env:COMPUTERNAME
$CurrentDomain = $env:USERDNSDOMAIN
$CurrentComputerFQDN = "$CurrentComputer.$CurrentDomain"

Write-Host "Current computer: $CurrentComputerFQDN" -ForegroundColor Cyan

# Read and parse JSON file
try {
    $jsonContent = Get-Content -Path $AttackPath -Raw
    $graphData = $jsonContent | ConvertFrom-Json
    
    Write-Host "Successfully parsed JSON data" -ForegroundColor Green
} catch {
    Write-Error "Failed to parse the JSON file: $_"
    Stop-Transcript
    exit
}

# Identify computers and users in the nodes
$computers = @{}
$users = @{}

foreach ($nodeKey in $graphData.data.nodes.PSObject.Properties.Name) {
    $node = $graphData.data.nodes.$nodeKey
    
    if ($node.kind -eq "Computer") {
        $computerName = $node.label -replace '\..*$' # Remove domain suffix
        $computers[$nodeKey] = @{
            Name = $computerName
            FullName = $node.label
        }
    }
    elseif ($node.kind -eq "User") {
        $userName = $node.label -replace '@.*$' # Remove domain suffix
        $users[$nodeKey] = @{
            Name = $userName
            FullName = $node.label
        }
    }
}

# Find all HasSession edges where this computer is the source
$sessionEdges = @()
$thisComputerNodeId = $null

# Get current computer name variations for matching
$currentComputerShort = $env:COMPUTERNAME  # e.g., "RAVEN"
$currentComputerFQDN = $CurrentComputerFQDN  # e.g., "RAVEN.GHOST.LOCAL"

Write-Host "Looking for computer matches:" -ForegroundColor Cyan
Write-Host "  Short name: $currentComputerShort" -ForegroundColor Cyan
Write-Host "  FQDN: $currentComputerFQDN" -ForegroundColor Cyan

# Find the node ID for the current computer with flexible matching
foreach ($nodeId in $computers.Keys) {
    $computerInfo = $computers[$nodeId]
    $jsonComputerName = $computerInfo.Name      # Short name from JSON (e.g., "RAVEN")
    $jsonComputerFull = $computerInfo.FullName  # Full name from JSON (e.g., "RAVEN.GHOST.LOCAL")
    
    Write-Host "  Checking JSON computer: '$jsonComputerName' / '$jsonComputerFull'" -ForegroundColor Gray
    
    # Try multiple matching strategies:
    # 1. Short name to short name
    # 2. FQDN to full name
    # 3. Short name to full name (extract short from JSON full name)
    # 4. FQDN to short name (extract short from current FQDN)
    
    $isMatch = $false
    
    # Strategy 1: Direct short name match
    if ($jsonComputerName -eq $currentComputerShort) {
        $isMatch = $true
        Write-Host "    Match found: Short name to short name" -ForegroundColor Green
    }
    # Strategy 2: Direct FQDN match
    elseif ($jsonComputerFull -eq $currentComputerFQDN) {
        $isMatch = $true
        Write-Host "    Match found: FQDN to FQDN" -ForegroundColor Green
    }
    # Strategy 3: Compare short names (extract from both if needed)
    elseif ($jsonComputerFull -match '^([^.]+)\.') {
        $jsonShortFromFull = $matches[1]
        if ($jsonShortFromFull -eq $currentComputerShort) {
            $isMatch = $true
            Write-Host "    Match found: Short name extracted from JSON FQDN ($jsonShortFromFull)" -ForegroundColor Green
        }
    }
    
    if ($isMatch) {
        $thisComputerNodeId = $nodeId
        Write-Host "Selected computer node ID: $thisComputerNodeId" -ForegroundColor Green
        break
    }
}

if (-not $thisComputerNodeId) {
    Write-Host "Current computer ($CurrentComputer) not found in the JSON data." -ForegroundColor Yellow
    Stop-Transcript
    exit
}

Write-Host "Found current computer in JSON data with node ID: $thisComputerNodeId" -ForegroundColor Green

# Find all HasSession edges for this computer
foreach ($edge in $graphData.data.edges) {
    if ($edge.kind -eq "HasSession" -and $edge.source -eq $thisComputerNodeId) {
        $sessionEdges += $edge
    }
}

if ($sessionEdges.Count -eq 0) {
    Write-Host "No session relationships found for this computer." -ForegroundColor Yellow
    Stop-Transcript
    exit
}

Write-Host "Found $($sessionEdges.Count) session relationships for this computer." -ForegroundColor Green

# Process each session edge
foreach ($edge in $sessionEdges) {
    $targetNodeId = $edge.target
    
    # Skip if target is not a user
    if (-not $users.ContainsKey($targetNodeId)) {
        Write-Host "Target node $targetNodeId is not a user. Skipping." -ForegroundColor Yellow
        continue
    }
    
    $targetUser = $users[$targetNodeId]
    $userName = $targetUser.Name
    $userFullName = $targetUser.FullName
    
    Write-Host "`n=== Processing user: $userFullName ===" -ForegroundColor Cyan
    
    # Standard password for all target users
    $Password = "password"
    
    # ==========================================================================
    # Add the user to the local Administrators group
    # ==========================================================================
    try {
        # Check if the user is already a member of the Administrators group
        $localAdminGroup = [ADSI]"WinNT://$CurrentComputer/Administrators,group"
        $existingMembers = @($localAdminGroup.Invoke("Members")) | ForEach-Object {
            $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        }
        
        if ($existingMembers -contains $userName) {
            Write-Host "User '$userName' is already a member of the local Administrators group." -ForegroundColor Yellow
        } else {
            # Add the user to the Administrators group using net localgroup
            $netOutput = net localgroup "Administrators" "$CurrentDomain\$userName" /add 2>&1
            
            if ($netOutput -match "successfully") {
                Write-Host "User '$userName' has been added to the local Administrators group." -ForegroundColor Green
            } else {
                Write-Host "Failed to add user to Administrators group: $netOutput" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Error adding user to Administrators group: $_" -ForegroundColor Red
    }
    
    # ==========================================================================
    # Create the timed task (runs every 10 minutes)
    # ==========================================================================
    $timedTaskName = "PowerShellTask_$userName"
    $timedDescription = "Scheduled task that runs PowerShell every 10 minutes for $userFullName"

    # Action to execute (simple PowerShell)
    $timedAction = New-ScheduledTaskAction -Execute "powershell.exe"

    # Create a trigger to run every 10 minutes
    $timedTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1825) # 5 years

    # Settings
    $timedSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Remove the timed task if it already exists
    $existingTimedTask = Get-ScheduledTask -TaskName $timedTaskName -ErrorAction SilentlyContinue
    if ($existingTimedTask) {
        Write-Host "Task '$timedTaskName' already exists. Removing it..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $timedTaskName -Confirm:$false
        Write-Host "Task '$timedTaskName' removed." -ForegroundColor Yellow
    }

    # Create the timed scheduled task
    try {
        Register-ScheduledTask -TaskName $timedTaskName `
                               -Action $timedAction `
                               -Trigger $timedTrigger `
                               -Settings $timedSettings `
                               -User "$CurrentDomain\$userName" `
                               -Password $Password `
                               -Description $timedDescription `
                               -RunLevel Highest `
                               -Force
        
        Write-Host "Task '$timedTaskName' created successfully!" -ForegroundColor Green
        
        # Run the timed task immediately
        Start-ScheduledTask -TaskName $timedTaskName
        Write-Host "Task '$timedTaskName' started!" -ForegroundColor Green
    } catch {
        Write-Host "Error creating timed scheduled task: $_" -ForegroundColor Red
    }

    # ==========================================================================
    # Create the reboot task
    # ==========================================================================
    $rebootTaskName = "PowerShellRebootTask_$userName"
    $rebootDescription = "Scheduled task that runs PowerShell on system reboot for $userFullName"

    # Action to execute (simple PowerShell)
    $rebootAction = New-ScheduledTaskAction -Execute "powershell.exe"

    # Create a trigger for system startup
    $rebootTrigger = New-ScheduledTaskTrigger -AtStartup

    # Settings
    $rebootSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Remove the reboot task if it already exists
    $existingRebootTask = Get-ScheduledTask -TaskName $rebootTaskName -ErrorAction SilentlyContinue
    if ($existingRebootTask) {
        Write-Host "Task '$rebootTaskName' already exists. Removing it..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $rebootTaskName -Confirm:$false
        Write-Host "Task '$rebootTaskName' removed." -ForegroundColor Yellow
    }

    # Create the reboot scheduled task
    try {
        Register-ScheduledTask -TaskName $rebootTaskName `
                               -Action $rebootAction `
                               -Trigger $rebootTrigger `
                               -Settings $rebootSettings `
                               -User "$CurrentDomain\$userName" `
                               -Password $Password `
                               -Description $rebootDescription `
                               -RunLevel Highest `
                               -Force
        
        Write-Host "Reboot task '$rebootTaskName' created successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Error creating reboot scheduled task: $_" -ForegroundColor Red
    }
}

Write-Host "`nSession creation completed for all users with sessions on this computer!" -ForegroundColor Cyan

# End logging
Stop-Transcript