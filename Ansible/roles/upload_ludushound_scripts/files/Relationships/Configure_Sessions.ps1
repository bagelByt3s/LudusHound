param(
    [string]$f,         # File path
    [int]$c = 0,        # Count of entries to process (0 means all entries)
    [switch]$fullSend   # Full send flag (process all entries)
)

# Check if the file path is provided
if (-not $f) {
    Write-Host "Please provide the path to the JSON file using the -f argument."
    exit
}

# Check if the file exists
if (-not (Test-Path $f)) {
    Write-Host "The file '$f' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\Configure_Session"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Read and parse the JSON file
try {
    $jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json
} catch {
    Write-Host "Failed to parse the JSON file. Please check the file format."
    exit
}

# Determine how many entries to process
if ($fullSend) {
    # If -fullSend is provided, process all entries
    $jsonContent = $jsonContent
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $jsonContent = $jsonContent[0..($c - 1)]  # Get the first $c entries
}

# Start logging to the log file
Start-Transcript -Path $logFile

# Script to create scheduled tasks based on JSON relationships
# The script reads a JSON file and creates tasks for each target user that has a session on this computer

# Get the current computer name
$CurrentComputer = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
Write-Host "Current computer: $CurrentComputer" -ForegroundColor Cyan

# Find relationships where this computer is the source
$MatchingRelationships = $jsonContent | Where-Object { $_.source -eq $CurrentComputer -and ![string]::IsNullOrEmpty($_.target) }

if ($MatchingRelationships.Count -eq 0) {
    Write-Host "No matching relationships found for this computer" -ForegroundColor Yellow
    Stop-Transcript
    exit
}

Write-Host "Found $($MatchingRelationships.Count) matching relationships for this computer" -ForegroundColor Green

# Process each matching relationship
foreach ($Relation in $MatchingRelationships) {
    $TargetUser = $Relation.target
    $UserName = $TargetUser.Split('@')[0]
    
    Write-Host "`n=== Processing user: $TargetUser ===" -ForegroundColor Cyan
    
    # Standard password for all target users
    $Password = "password"
    
    # ==========================================================================
    # Add the user to the local Administrators group
    # ==========================================================================
    try {
        # Check if the user is already a member of the Administrators group
        $AdminGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
        $ExistingMembers = @($AdminGroup.Invoke("Members")) | ForEach-Object {
            $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        }
        
        if ($ExistingMembers -contains $UserName) {
            Write-Host "User '$UserName' is already a member of the local Administrators group." -ForegroundColor Yellow
        } else {
            # Add the user to the Administrators group
            $AdminGroup.Add("WinNT://$env:USERDNSDOMAIN/$UserName,user")
            Write-Host "User '$UserName' has been added to the local Administrators group." -ForegroundColor Green
        }
    } catch {
        Write-Host "Error adding user to Administrators group: $_" -ForegroundColor Red
    }
    
    # ==========================================================================
    # Create the timed task (runs every 10 minutes)
    # ==========================================================================
    $TimedTaskName = "PowerShellTask_$UserName"
    $TimedDescription = "Scheduled task that runs PowerShell every 10 minutes for $TargetUser"

    # Action to execute (simple PowerShell)
    $TimedAction = New-ScheduledTaskAction -Execute "powershell.exe"

    # Create a trigger to run every 10 minutes
    $TimedTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1825) # 5 years

    # Settings
    $TimedSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Remove the timed task if it already exists
    $ExistingTimedTask = Get-ScheduledTask -TaskName $TimedTaskName -ErrorAction SilentlyContinue
    if ($ExistingTimedTask) {
        Write-Host "Task '$TimedTaskName' already exists. Removing it..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TimedTaskName -Confirm:$false
        Write-Host "Task '$TimedTaskName' removed." -ForegroundColor Yellow
    }

    # Create the timed scheduled task
    try {
        Register-ScheduledTask -TaskName $TimedTaskName `
                               -Action $TimedAction `
                               -Trigger $TimedTrigger `
                               -Settings $TimedSettings `
                               -User $TargetUser `
                               -Password $Password `
                               -Description $TimedDescription `
                               -RunLevel Highest `
                               -Force
        
        Write-Host "Task '$TimedTaskName' created successfully!" -ForegroundColor Green
        
        # Run the timed task immediately
        Start-ScheduledTask -TaskName $TimedTaskName
        Write-Host "Task '$TimedTaskName' started!" -ForegroundColor Green
    } catch {
        Write-Host "Error creating timed scheduled task: $_" -ForegroundColor Red
    }

    # ==========================================================================
    # Create the reboot task
    # ==========================================================================
    $RebootTaskName = "PowerShellRebootTask_$UserName"
    $RebootDescription = "Scheduled task that runs PowerShell on system reboot for $TargetUser"

    # Action to execute (simple PowerShell)
    $RebootAction = New-ScheduledTaskAction -Execute "powershell.exe"

    # Create a trigger for system startup
    $RebootTrigger = New-ScheduledTaskTrigger -AtStartup

    # Settings
    $RebootSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Remove the reboot task if it already exists
    $ExistingRebootTask = Get-ScheduledTask -TaskName $RebootTaskName -ErrorAction SilentlyContinue
    if ($ExistingRebootTask) {
        Write-Host "Task '$RebootTaskName' already exists. Removing it..." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $RebootTaskName -Confirm:$false
        Write-Host "Task '$RebootTaskName' removed." -ForegroundColor Yellow
    }

    # Create the reboot scheduled task
    try {
        Register-ScheduledTask -TaskName $RebootTaskName `
                               -Action $RebootAction `
                               -Trigger $RebootTrigger `
                               -Settings $RebootSettings `
                               -User $TargetUser `
                               -Password $Password `
                               -Description $RebootDescription `
                               -RunLevel Highest `
                               -Force
        
        Write-Host "Reboot task '$RebootTaskName' created successfully!" -ForegroundColor Green
    } catch {
        Write-Host "Error creating reboot scheduled task: $_" -ForegroundColor Red
    }
}

Write-Host "`nTask creation and user configuration completed for all matching users!" -ForegroundColor Cyan

# End logging
Stop-Transcript