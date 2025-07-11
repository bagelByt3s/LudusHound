param(
    [string]$OUFile,         # File path for OUs.json
    [string]$UsersFile,      # File path for Users.json
    [int]$c = 0,             # Count of entries to process (0 means all entries)
    [switch]$fullSend        # Full send flag (process all entries)
)

# Check if the file paths are provided
if (-not $OUFile) {
    Write-Host "Please provide the path to the OUs JSON file using the -OUFile argument."
    exit
}

if (-not $UsersFile) {
    Write-Host "Please provide the path to the Users JSON file using the -UsersFile argument."
    exit
}

# Check if the files exist
if (-not (Test-Path $OUFile)) {
    Write-Host "The file '$OUFile' does not exist."
    exit
}

if (-not (Test-Path $UsersFile)) {
    Write-Host "The file '$UsersFile' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\Configure_User_OU"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Start logging to the log file
Start-Transcript -Path $logFile

Write-Host "Starting OU Membership Configuration..."
Write-Host "OU File: $OUFile"
Write-Host "Users File: $UsersFile"

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

# Read and parse the Users JSON file
try {
    $usersJsonContent = Get-Content -Path $UsersFile | Out-String | ConvertFrom-Json
    Write-Host "Successfully loaded Users data. Found $($usersJsonContent.Count) users."
} catch {
    Write-Host "Failed to parse the Users JSON file. Please check the file format."
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

# Filter Users by current domain
$domainUsers = @()
foreach ($userEntry in $usersJsonContent) {
    $user = $userEntry[0]  # Access the first element of the array
    if (-not $currentDomain -or $user.domain -eq $currentDomain) {
        $domainUsers += $userEntry
    }
}

Write-Host "Found $($domainUsers.Count) Users in current domain ($currentDomain)"

# Determine how many entries to process for Users
if ($fullSend -or $c -eq 0) {
    # If -fullSend is provided or c is 0, process all entries
    $usersToProcess = $domainUsers
    Write-Host "Processing all Users in current domain"
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $entriesToProcess = [Math]::Min($c, $domainUsers.Count)
    $usersToProcess = $domainUsers[0..($entriesToProcess - 1)]  # Get the first $c entries
    Write-Host "Processing first $entriesToProcess Users in current domain"
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

# Function to verify if user is in the correct OU using Get-ADUser
function Verify-UserOU {
    param(
        [string]$samAccountName,
        [string]$expectedOU
    )
    
    try {
        # Get the actual user from AD
        $adUser = Get-ADUser -Identity $samAccountName -Properties DistinguishedName -ErrorAction Stop
        $actualDN = $adUser.DistinguishedName
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
        Write-Host "  Error retrieving user with Get-ADUser: $_" -ForegroundColor Red
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

if ($usersToProcess.Count -eq 0) {
    Write-Host "No users found in the current domain to process."
    Stop-Transcript
    exit
}

if ($ousToProcess.Count -eq 0) {
    Write-Host "No OUs found in the current domain to process."
    Stop-Transcript
    exit
}

foreach ($userEntry in $usersToProcess) {
    $user = $userEntry[0]  # Access the first element of the array
    $userDN = $user.distinguishedname
    $userSamAccountName = $user.samaccountname  # Assuming the JSON file has this field
    if (-not $userSamAccountName) {
        # If samaccountname is not available, try to extract it from the DN
        try {
            $userSamAccountName = ($userDN -split ',')[0] -replace 'CN=', ''
            Write-Host "  Extracted samAccountName from DN: $userSamAccountName"
        } catch {
            Write-Host "  Could not extract samAccountName from DN: $_" -ForegroundColor Red
            $errorCount++
            continue
        }
    }
    
    $userDomain = Get-DomainFromDN -dn $userDN
    $userOUPath = Get-OUPathFromDN -dn $userDN
    
    Write-Host "Processing user: $($user.name) ($userSamAccountName)"
    Write-Host "  Distinguished Name from file: $userDN"
    Write-Host "  Domain: $userDomain"
    Write-Host "  OU Path from file: $userOUPath"
    
    # Skip users not in the current domain
    if ($currentDomain -and $user.domain -ne $currentDomain) {
        Write-Host "  Skipping user: not in current domain ($currentDomain)" -ForegroundColor Gray
        $skippedCount++
        continue
    }
    
    # Check if user is already in an OU according to the JSON file
    $userCurrentOU = ""
    if ($userDN -match "OU=") {
        $userCurrentOU = $userDN -replace "^CN=[^,]+,", ""
        Write-Host "  Expected OU (from user DN): $userCurrentOU"
    } else {
        Write-Host "  User has no OU specified in the JSON file" -ForegroundColor Yellow
    }
    
    # Get the expected target OU directly from the user's DN
    $expectedOU = $null
    if ($userDN -match "OU=") {
        # Extract the full OU path from the user's DN
        $expectedOUPath = $userDN -replace "^CN=[^,]+,", ""
        
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
                name = "Expected OU from user DN"
                distinguishedname = $expectedOUPath
                domain = $userDomain
            }
        }
    } else {
        # If user has no OU in DN, try to find a matching OU based on other attributes
        foreach ($ouEntry in $ousToProcess) {
            $ou = $ouEntry[0]  # Access the first element of the array
            if ($ou.domain -eq $user.domain) {
                # Look for department or role indicators in the user object
                if ($user.description -and $ou.description -and 
                    $user.description -match $ou.description) {
                    $expectedOU = $ou
                    break
                }
            }
        }
    }
    
    # Use the expected OU as the matching OU
    $matchingOU = $expectedOU
    
    if ($matchingOU) {
        Write-Host "  Found matching OU: $($matchingOU.name) ($($matchingOU.distinguishedname))"
        
        # Use Get-ADUser to verify the actual current OU of the user
        $ouVerification = Verify-UserOU -samAccountName $userSamAccountName -expectedOU $matchingOU.distinguishedname
        
        Write-Host "  Current AD OU: $($ouVerification.ActualOU)"
        Write-Host "  Expected OU: $($ouVerification.ExpectedOU)"
        
        if ($ouVerification.IsCorrect) {
            Write-Host "  User is in the correct OU according to AD" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host "  User is NOT in the correct OU" -ForegroundColor Yellow
            $incorrectOUCount++
            
            # Move the user to the correct OU
            try {
                Write-Host "  Moving user $($user.name) from $($ouVerification.ActualOU) to $($matchingOU.distinguishedname)" -ForegroundColor Cyan
                Move-ADObject -Identity $ouVerification.DistinguishedName -TargetPath $matchingOU.distinguishedname -Confirm:$false
                Write-Host "  Successfully moved user to correct OU" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "  Error moving user: $_" -ForegroundColor Red
                $errorCount++
            }
        }
    } else {
        Write-Host "  No matching OU found for user $($user.name)" -ForegroundColor Yellow
        
        # Try to get the current AD OU anyway for reporting
        try {
            $adUser = Get-ADUser -Identity $userSamAccountName -Properties DistinguishedName -ErrorAction Stop
            $actualDN = $adUser.DistinguishedName
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
Write-Host "Successfully processed: $successCount users"
Write-Host "Users in incorrect OUs: $incorrectOUCount"
Write-Host "Errors encountered: $errorCount users"
Write-Host "Skipped (not in current domain): $skippedCount users"

# Stop logging
Stop-Transcript