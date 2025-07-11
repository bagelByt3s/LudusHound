param(
    [string]$OUFile,         # File path for OUs.json
    [string]$GroupsFile,     # File path for Groups.json (changed from ComputersFile)
    [int]$c = 0,             # Count of entries to process (0 means all entries)
    [switch]$fullSend        # Full send flag (process all entries)
)

# Check if the file paths are provided
if (-not $OUFile) {
    Write-Host "Please provide the path to the OUs JSON file using the -OUFile argument."
    exit
}

if (-not $GroupsFile) {
    Write-Host "Please provide the path to the Groups JSON file using the -GroupsFile argument."
    exit
}

# Check if the files exist
if (-not (Test-Path $OUFile)) {
    Write-Host "The file '$OUFile' does not exist."
    exit
}

if (-not (Test-Path $GroupsFile)) {
    Write-Host "The file '$GroupsFile' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\Configure_Group_OU"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Start logging to the log file
Start-Transcript -Path $logFile

Write-Host "Starting OU Membership Configuration for Groups..."
Write-Host "OU File: $OUFile"
Write-Host "Groups File: $GroupsFile"

# Check if the ActiveDirectory module is available and load it if needed
if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "Active Directory module loaded successfully."
    } catch {
        Write-Host "Error loading Active Directory module: $_" -ForegroundColor Red
        Write-Host "Please ensure the ActiveDirectory module is installed using 'Install-WindowsFeature RSAT-AD-PowerShell'."
        Stop-Transcript
        exit
    }
}

# Get the current domain of the DC
try {
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    if (-not $currentDomain) {
        # Alternative method if the above fails
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    Write-Host "Current domain: $currentDomain"
} catch {
    Write-Host "Error determining current domain: $_" -ForegroundColor Red
    Write-Host "Using default domain detection method..."
    try {
        # Another fallback method
        $currentDomain = [System.Net.Dns]::GetHostEntry([string]$env:computername).HostName.Split('.')[1..100] -join '.'
        Write-Host "Current domain (using DNS): $currentDomain"
    } catch {
        Write-Host "Failed to determine current domain. Will process all domains." -ForegroundColor Yellow
        $currentDomain = $null
    }
}

# Read and parse the OU JSON file
try {
    $ouJsonContent = Get-Content -Path $OUFile | Out-String | ConvertFrom-Json
    Write-Host "Successfully loaded OU data. Found $($ouJsonContent.Count) OUs."
} catch {
    Write-Host "Failed to parse the OU JSON file. Please check the file format."
    Write-Host "Error: $_"
    Stop-Transcript
    exit
}

# Read and parse the Groups JSON file
try {
    $groupsJsonContent = Get-Content -Path $GroupsFile | Out-String | ConvertFrom-Json
    Write-Host "Successfully loaded Groups data. Found $($groupsJsonContent.Count) groups."
} catch {
    Write-Host "Failed to parse the Groups JSON file. Please check the file format."
    Write-Host "Error: $_"
    Stop-Transcript
    exit
}

# Filter OUs by current domain
$domainOUs = @()
foreach ($ouEntry in $ouJsonContent) {
    $ou = $ouEntry[0]  # Access the first element of the array
    if (-not $currentDomain -or $ou.domain -eq $currentDomain) {
        $domainOUs += $ouEntry
    }
}

Write-Host "Found $($domainOUs.Count) OUs in current domain ($currentDomain)"

# Determine how many entries to process for OUs
if ($fullSend -or $c -eq 0) {
    # If -fullSend is provided or c is 0, process all entries
    $ousToProcess = $domainOUs
    Write-Host "Processing all OUs in current domain"
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $entriesToProcess = [Math]::Min($c, $domainOUs.Count)
    $ousToProcess = $domainOUs[0..($entriesToProcess - 1)]  # Get the first $c entries
    Write-Host "Processing first $entriesToProcess OUs in current domain"
}

# Filter Groups by current domain
$domainGroups = @()
foreach ($groupEntry in $groupsJsonContent) {
    $group = $groupEntry[0]  # Access the first element of the array
    if (-not $currentDomain -or $group.domain -eq $currentDomain) {
        $domainGroups += $groupEntry
    }
}

Write-Host "Found $($domainGroups.Count) Groups in current domain ($currentDomain)"

# Determine how many entries to process for Groups
if ($fullSend -or $c -eq 0) {
    # If -fullSend is provided or c is 0, process all entries
    $groupsToProcess = $domainGroups
    Write-Host "Processing all Groups in current domain"
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $entriesToProcess = [Math]::Min($c, $domainGroups.Count)
    $groupsToProcess = $domainGroups[0..($entriesToProcess - 1)]  # Get the first $c entries
    Write-Host "Processing first $entriesToProcess Groups in current domain"
}

# Function to extract domain components from distinguishedname
function Get-DomainFromDN {
    param(
        [string]$dn
    )
    
    $dcParts = $dn -split ',' | Where-Object { $_ -match '^DC=' }
    $domain = ($dcParts -replace 'DC=', '') -join '.'
    return $domain
}

# Function to extract OU path from distinguishedname
function Get-OUPathFromDN {
    param(
        [string]$dn
    )
    
    $parts = $dn -split ','
    $ouParts = $parts | Where-Object { $_ -match '^OU=' }
    return $ouParts -join ','
}

# Function to verify if group is in the correct OU using Get-ADGroup
function Verify-GroupOU {
    param(
        [string]$groupName,
        [string]$expectedOU
    )
    
    try {
        # Get the actual group from AD
        $adGroup = Get-ADGroup -Identity $groupName -Properties DistinguishedName -ErrorAction Stop
        $actualDN = $adGroup.DistinguishedName
        $actualOU = $actualDN -replace "^CN=[^,]+,", ""
        
        # Compare with expected OU
        $isCorrectOU = $actualOU -eq $expectedOU
        
        return @{
            IsCorrect = $isCorrectOU
            ActualOU = $actualOU
            ExpectedOU = $expectedOU
            DistinguishedName = $actualDN
        }
    } catch {
        Write-Host "  Error retrieving group with Get-ADGroup: $_" -ForegroundColor Red
        return @{
            IsCorrect = $false
            ActualOU = "Error"
            ExpectedOU = $expectedOU
            DistinguishedName = "Error: $($_)"
        }
    }
}

# Main processing logic
$successCount = 0
$errorCount = 0
$skippedCount = 0
$incorrectOUCount = 0

if ($groupsToProcess.Count -eq 0) {
    Write-Host "No groups found in the current domain to process."
    Stop-Transcript
    exit
}

if ($ousToProcess.Count -eq 0) {
    Write-Host "No OUs found in the current domain to process."
    Stop-Transcript
    exit
}

foreach ($groupEntry in $groupsToProcess) {
    $group = $groupEntry[0]  # Access the first element of the array
    $groupDN = $group.distinguishedname
    
    # Extract the group name for AD lookup
    $groupName = $null
    if ($group.samaccountname) {
        # If samAccountName exists, use it
        $groupName = $group.samaccountname
    } else {
        # Otherwise extract from DN
        try {
            $groupName = ($groupDN -split ',')[0] -replace 'CN=', ''
            Write-Host "  Extracted group name from DN: $groupName"
        } catch {
            Write-Host "  Could not extract group name from DN: $_" -ForegroundColor Red
            $errorCount++
            continue
        }
    }
    
    $groupDomain = Get-DomainFromDN -dn $groupDN
    $groupOUPath = Get-OUPathFromDN -dn $groupDN
    
    Write-Host "Processing group: $($group.name) ($groupName)"
    Write-Host "  Distinguished Name from file: $groupDN"
    Write-Host "  Domain: $groupDomain"
    Write-Host "  OU Path from file: $groupOUPath"
    
    # Skip groups not in the current domain
    if ($currentDomain -and $group.domain -ne $currentDomain) {
        Write-Host "  Skipping group: not in current domain ($currentDomain)" -ForegroundColor Gray
        $skippedCount++
        continue
    }
    
    # Get the expected target OU directly from the group's DN
    $expectedOU = $null
    if ($groupDN -match "OU=") {
        # Extract the full OU path from the group's DN
        $expectedOUPath = $groupDN -replace "^CN=[^,]+,", ""
        
        # Find the exact matching OU from the OU JSON file
        foreach ($ouEntry in $ousToProcess) {
            $ou = $ouEntry[0]  # Access the first element of the array
            if ($ou.distinguishedname -eq $expectedOUPath) {
                $expectedOU = $ou
                break
            }
        }
        
        # If no exact match was found, create a temporary OU object with the expected path
        if (-not $expectedOU) {
            $expectedOU = @{
                name = "Expected OU from group DN"
                distinguishedname = $expectedOUPath
                domain = $groupDomain
            }
        }
        
        Write-Host "  Expected OU (from group DN): $expectedOUPath"
    } else {
        # For groups in the default Users container, try to determine where they should go
        # based on naming convention or other attributes
        Write-Host "  Group is in the default container" -ForegroundColor Yellow
        
        # Try to find a matching OU based on group name pattern or purpose
        foreach ($ouEntry in $ousToProcess) {
            $ou = $ouEntry[0]  # Access the first element of the array
            
            # Example logic: Match group naming pattern with OU
            # This should be customized based on your naming convention
            if ($groupName -match "^SEC-" -and $ou.name -match "SECURITY") {
                $expectedOU = $ou
                Write-Host "  Matched to OU based on 'SEC-' prefix: $($ou.distinguishedname)" -ForegroundColor Cyan
                break
            } elseif ($groupName -match "^APP-" -and $ou.name -match "APPLICATION") {
                $expectedOU = $ou
                Write-Host "  Matched to OU based on 'APP-' prefix: $($ou.distinguishedname)" -ForegroundColor Cyan
                break
            } elseif ($groupName -match "^DL-" -and $ou.name -match "DISTRIBUTION") {
                $expectedOU = $ou
                Write-Host "  Matched to OU based on 'DL-' prefix: $($ou.distinguishedname)" -ForegroundColor Cyan
                break
            } elseif ($groupName -match "^DEPT-" -and $ou.name -match "DEPARTMENTS") {
                $expectedOU = $ou
                Write-Host "  Matched to OU based on 'DEPT-' prefix: $($ou.distinguishedname)" -ForegroundColor Cyan
                break
            } elseif ($groupName -match "^PROJ-" -and $ou.name -match "PROJECTS") {
                $expectedOU = $ou
                Write-Host "  Matched to OU based on 'PROJ-' prefix: $($ou.distinguishedname)" -ForegroundColor Cyan
                break
            } elseif ($groupName -match "^ROLE-" -and $ou.name -match "ROLES") {
                $expectedOU = $ou
                Write-Host "  Matched to OU based on 'ROLE-' prefix: $($ou.distinguishedname)" -ForegroundColor Cyan
                break
            }
            
            # Further refinement based on group purpose
            if (-not $expectedOU) {
                if ($groupName -match "ACCT" -and $ou.name -match "ACCOUNTING") {
                    $expectedOU = $ou
                    Write-Host "  Matched to OU based on 'ACCT' in name: $($ou.distinguishedname)" -ForegroundColor Cyan
                    break
                } elseif ($groupName -match "SALES" -and $ou.name -match "SALES") {
                    $expectedOU = $ou
                    Write-Host "  Matched to OU based on 'SALES' in name: $($ou.distinguishedname)" -ForegroundColor Cyan
                    break
                } elseif ($groupName -match "MKTG" -and $ou.name -match "MARKETING") {
                    $expectedOU = $ou
                    Write-Host "  Matched to OU based on 'MKTG' in name: $($ou.distinguishedname)" -ForegroundColor Cyan
                    break
                } elseif ($groupName -match "IT" -and $ou.name -match "IT") {
                    $expectedOU = $ou
                    Write-Host "  Matched to OU based on 'IT' in name: $($ou.distinguishedname)" -ForegroundColor Cyan
                    break
                } elseif ($groupName -match "HR" -and $ou.name -match "HUMAN RESOURCES") {
                    $expectedOU = $ou
                    Write-Host "  Matched to OU based on 'HR' in name: $($ou.distinguishedname)" -ForegroundColor Cyan
                    break
                } elseif ($groupName -match "ADMIN" -and $ou.name -match "ADMINISTRATION") {
                    $expectedOU = $ou
                    Write-Host "  Matched to OU based on 'ADMIN' in name: $($ou.distinguishedname)" -ForegroundColor Cyan
                    break
                }
            }
        }
    }
    
    if ($expectedOU) {
        Write-Host "  Target OU: $($expectedOU.name) ($($expectedOU.distinguishedname))"
        
        # Use Get-ADGroup to verify the actual current OU of the group
        $ouVerification = Verify-GroupOU -groupName $groupName -expectedOU $expectedOU.distinguishedname
        
        Write-Host "  Current AD OU: $($ouVerification.ActualOU)"
        Write-Host "  Expected OU: $($ouVerification.ExpectedOU)"
        
        if ($ouVerification.IsCorrect) {
            Write-Host "  Group is in the correct OU according to AD" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host "  Group is NOT in the correct OU" -ForegroundColor Yellow
            $incorrectOUCount++
            
            # Move the group to the correct OU
            try {
                Write-Host "  Moving group $($group.name) from $($ouVerification.ActualOU) to $($expectedOU.distinguishedname)" -ForegroundColor Cyan
                Move-ADObject -Identity $ouVerification.DistinguishedName -TargetPath $expectedOU.distinguishedname -Confirm:$false
                Write-Host "  Successfully moved group to correct OU" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "  Error moving group: $_" -ForegroundColor Red
                $errorCount++
            }
        }
    } else {
        Write-Host "  No matching OU found for group $($group.name)" -ForegroundColor Yellow
        
        # Try to get the current AD OU anyway for reporting
        try {
            $adGroup = Get-ADGroup -Identity $groupName -Properties DistinguishedName -ErrorAction Stop
            $actualDN = $adGroup.DistinguishedName
            $actualOU = $actualDN -replace "^CN=[^,]+,", ""
            Write-Host "  Current AD OU: $actualOU" -ForegroundColor Gray
        } catch {
            Write-Host "  Could not retrieve current AD OU: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# Summary
Write-Host "Configuration complete!"
Write-Host "Successfully processed: $successCount groups"
Write-Host "Groups in incorrect OUs: $incorrectOUCount"
Write-Host "Errors encountered: $errorCount groups"
Write-Host "Skipped (not in current domain): $skippedCount groups"

# Stop logging
Stop-Transcript