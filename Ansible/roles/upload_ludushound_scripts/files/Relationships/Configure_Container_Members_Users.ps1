param(
    [string]$ContainerFile,  # File path for Containers.json
    [string]$UsersFile,      # File path for Users.json
    [int]$c = 0,             # Count of entries to process (0 means all entries)
    [switch]$fullSend        # Full send flag (process all entries)
)

# Check if the file paths are provided
if (-not $ContainerFile) {
    Write-Host "Please provide the path to the Containers JSON file using the -ContainerFile argument."
    exit
}

if (-not $UsersFile) {
    Write-Host "Please provide the path to the Users JSON file using the -UsersFile argument."
    exit
}

# Check if the files exist
if (-not (Test-Path $ContainerFile)) {
    Write-Host "The file '$ContainerFile' does not exist."
    exit
}

if (-not (Test-Path $UsersFile)) {
    Write-Host "The file '$UsersFile' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\Configure_User_Container"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Start logging to the log file
Start-Transcript -Path $logFile

Write-Host "Starting Container Membership Configuration..."
Write-Host "Container File: $ContainerFile"
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

# Read and parse the Container JSON file
try {
    $containerJsonContent = Get-Content -Path $ContainerFile | Out-String | ConvertFrom-Json
    Write-Host "Successfully loaded Container data. Found $($containerJsonContent.Count) containers."
} catch {
    Write-Host "Failed to parse the Container JSON file. Please check the file format."
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

# Filter Containers by current domain
$domainContainers = @()
foreach ($containerEntry in $containerJsonContent) {
    $container = $containerEntry[0]  # Access the first element of the array
    if (-not $currentDomain -or $container.domain -eq $currentDomain) {
        $domainContainers += $containerEntry
    }
}

Write-Host "Found $($domainContainers.Count) Containers in current domain ($currentDomain)"

# Determine how many entries to process for Containers
if ($fullSend -or $c -eq 0) {
    # If -fullSend is provided or c is 0, process all entries
    $containersToProcess = $domainContainers
    Write-Host "Processing all Containers in current domain"
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $entriesToProcess = [Math]::Min($c, $domainContainers.Count)
    $containersToProcess = $domainContainers[0..($entriesToProcess - 1)]  # Get the first $c entries
    Write-Host "Processing first $entriesToProcess Containers in current domain"
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

# Function to extract Container path from distinguishedname
function Get-ContainerPathFromDN {
    param(
        [string]$dn
    )
    
    $parts = $dn -split ','
    $containerParts = $parts | Where-Object { $_ -match '^CN=' -and $_ -notmatch '^CN=[^,]+$' }
    return $containerParts -join ','
}

# Function to verify if user is in the correct Container using Get-ADUser
function Verify-UserContainer {
    param(
        [string]$samAccountName,
        [string]$expectedContainer
    )
    
    try {
        # Get the actual user from AD
        $adUser = Get-ADUser -Identity $samAccountName -Properties DistinguishedName -ErrorAction Stop
        $actualDN = $adUser.DistinguishedName
        $actualContainer = $actualDN -replace "^CN=[^,]+,", ""
        
        # Compare with expected Container
        $isCorrectContainer = $actualContainer -eq $expectedContainer
        
        return @{
            IsCorrect = $isCorrectContainer
            ActualContainer = $actualContainer
            ExpectedContainer = $expectedContainer
            DistinguishedName = $actualDN
        }
    } catch {
        Write-Host "  Error retrieving user with Get-ADUser: $_" -ForegroundColor Red
        return @{
            IsCorrect = $false
            ActualContainer = "Error"
            ExpectedContainer = $expectedContainer
            DistinguishedName = "Error: $($_)"
        }
    }
}

# Main processing logic
$successCount = 0
$errorCount = 0
$skippedCount = 0
$incorrectContainerCount = 0

if ($usersToProcess.Count -eq 0) {
    Write-Host "No users found in the current domain to process."
    Stop-Transcript
    exit
}

if ($containersToProcess.Count -eq 0) {
    Write-Host "No Containers found in the current domain to process."
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
    $userContainerPath = Get-ContainerPathFromDN -dn $userDN
    
    Write-Host "Processing user: $($user.name) ($userSamAccountName)"
    Write-Host "  Distinguished Name from file: $userDN"
    Write-Host "  Domain: $userDomain"
    Write-Host "  Container Path from file: $userContainerPath"
    
    # Skip users not in the current domain
    if ($currentDomain -and $user.domain -ne $currentDomain) {
        Write-Host "  Skipping user: not in current domain ($currentDomain)" -ForegroundColor Gray
        $skippedCount++
        continue
    }
    
    # Check if user is already in a Container according to the JSON file
    $userCurrentContainer = ""
    if ($userDN -match ",CN=") {
        $userCurrentContainer = $userDN -replace "^CN=[^,]+,", ""
        Write-Host "  Expected Container (from user DN): $userCurrentContainer"
    } else {
        Write-Host "  User has no Container specified in the JSON file" -ForegroundColor Yellow
    }
    
    # Get the expected target Container directly from the user's DN
    $expectedContainer = $null
    if ($userDN -match ",CN=") {
        # Extract the full Container path from the user's DN
        $expectedContainerPath = $userDN -replace "^CN=[^,]+,", ""
        
        # Find the exact matching Container from the Container JSON file
        foreach ($containerEntry in $containersToProcess) {
            $container = $containerEntry[0]  # Access the first element of the array
            if ($container.distinguishedname -eq $expectedContainerPath) {
                $expectedContainer = $container
                break
            }
        }
        
        # If no exact match was found, create a temporary Container object with the expected path
        if (-not $expectedContainer) {
            $expectedContainer = @{
                name = "Expected Container from user DN"
                distinguishedname = $expectedContainerPath
                domain = $userDomain
            }
        }
    } else {
        # If user has no Container in DN, try to find a matching Container based on other attributes
        foreach ($containerEntry in $containersToProcess) {
            $container = $containerEntry[0]  # Access the first element of the array
            if ($container.domain -eq $user.domain) {
                # Look for department or role indicators in the user object
                if ($user.description -and $container.description -and 
                    $user.description -match $container.description) {
                    $expectedContainer = $container
                    break
                }
            }
        }
    }
    
    # Use the expected Container as the matching Container
    $matchingContainer = $expectedContainer
    
    if ($matchingContainer) {
        Write-Host "  Found matching Container: $($matchingContainer.name) ($($matchingContainer.distinguishedname))"
        
        # Use Get-ADUser to verify the actual current Container of the user
        $containerVerification = Verify-UserContainer -samAccountName $userSamAccountName -expectedContainer $matchingContainer.distinguishedname
        
        Write-Host "  Current AD Container: $($containerVerification.ActualContainer)"
        Write-Host "  Expected Container: $($containerVerification.ExpectedContainer)"
        
        if ($containerVerification.IsCorrect) {
            Write-Host "  User is in the correct Container according to AD" -ForegroundColor Green
            $successCount++
        } else {
            Write-Host "  User is NOT in the correct Container" -ForegroundColor Yellow
            $incorrectContainerCount++
            
            # Move the user to the correct Container
            try {
                Write-Host "  Moving user $($user.name) from $($containerVerification.ActualContainer) to $($matchingContainer.distinguishedname)" -ForegroundColor Cyan
                Move-ADObject -Identity $containerVerification.DistinguishedName -TargetPath $matchingContainer.distinguishedname -Confirm:$false
                Write-Host "  Successfully moved user to correct Container" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "  Error moving user: $_" -ForegroundColor Red
                $errorCount++
            }
        }
    } else {
        Write-Host "  No matching Container found for user $($user.name)" -ForegroundColor Yellow
        
        # Try to get the current AD Container anyway for reporting
        try {
            $adUser = Get-ADUser -Identity $userSamAccountName -Properties DistinguishedName -ErrorAction Stop
            $actualDN = $adUser.DistinguishedName
            $actualContainer = $actualDN -replace "^CN=[^,]+,", ""
            Write-Host "  Current AD Container: $actualContainer" -ForegroundColor Gray
        } catch {
            Write-Host "  Could not retrieve current AD Container: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# Summary
Write-Host "Configuration complete!"
Write-Host "Successfully processed: $successCount users"
Write-Host "Users in incorrect Containers: $incorrectContainerCount"
Write-Host "Errors encountered: $errorCount users"
Write-Host "Skipped (not in current domain): $skippedCount users"

# Stop logging
Stop-Transcript