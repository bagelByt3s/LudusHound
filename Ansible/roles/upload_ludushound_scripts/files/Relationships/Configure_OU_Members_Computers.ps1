param(
    [string]$OUFile,         # File path for OUs.json
    [string]$ComputersFile,  # File path for Computers.json
    [int]$c = 0,             # Count of entries to process (0 means all entries)
    [switch]$fullSend        # Full send flag (process all entries)
)

# Check if the file paths are provided
if (-not $OUFile) {
    Write-Host "Please provide the path to the OUs JSON file using the -OUFile argument."
    exit
}

if (-not $ComputersFile) {
    Write-Host "Please provide the path to the Computers JSON file using the -ComputersFile argument."
    exit
}

# Check if the files exist
if (-not (Test-Path $OUFile)) {
    Write-Host "The file '$OUFile' does not exist."
    exit
}

if (-not (Test-Path $ComputersFile)) {
    Write-Host "The file '$ComputersFile' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\Configure_Computer_OU"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Start logging to the log file
Start-Transcript -Path $logFile

Write-Host "Starting OU Membership Configuration for Computers..."
Write-Host "OU File: $OUFile"
Write-Host "Computers File: $ComputersFile"

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

# Read and parse the Computers JSON file
try {
    $computersJsonContent = Get-Content -Path $ComputersFile | Out-String | ConvertFrom-Json
    Write-Host "Successfully loaded Computers data. Found $($computersJsonContent.Count) computers."
} catch {
    Write-Host "Failed to parse the Computers JSON file. Please check the file format."
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

# Filter Computers by current domain
$domainComputers = @()
foreach ($computerEntry in $computersJsonContent) {
    $computer = $computerEntry[0]  # Access the first element of the array
    if (-not $currentDomain -or $computer.domain -eq $currentDomain) {
        $domainComputers += $computerEntry
    }
}

Write-Host "Found $($domainComputers.Count) Computers in current domain ($currentDomain)"

# Determine how many entries to process for Computers
if ($fullSend -or $c -eq 0) {
    # If -fullSend is provided or c is 0, process all entries
    $computersToProcess = $domainComputers
    Write-Host "Processing all Computers in current domain"
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $entriesToProcess = [Math]::Min($c, $domainComputers.Count)
    $computersToProcess = $domainComputers[0..($entriesToProcess - 1)]  # Get the first $c entries
    Write-Host "Processing first $entriesToProcess Computers in current domain"
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

# Function to get the target container path from a DN (excluding the CN part)
function Get-TargetContainerFromDN {
    param(
        [string]$dn
    )
    
    # Remove the CN=ComputerName part from the DN
    $containerPath = $dn -replace "^CN=[^,]+,", ""
    
    # If there's no container path (meaning the DN was just CN=name,DC=domain,DC=com)
    # Then return just the domain part
    if ($containerPath -match "^DC=") {
        return $containerPath
    }
    
    return $containerPath
}

# Function to verify if computer is in the correct location using Get-ADComputer
function Verify-ComputerLocation {
    param(
        [string]$computerName,
        [string]$expectedLocation
    )
    
    try {
        # Get the actual computer from AD
        $adComputer = Get-ADComputer -Identity $computerName -Properties DistinguishedName -ErrorAction Stop
        $actualDN = $adComputer.DistinguishedName
        $actualLocation = $actualDN -replace "^CN=[^,]+,", ""
        
        # If both expected and actual locations don't have any OU parts, they're both in the domain root
        $expectedHasOU = $expectedLocation -match "OU="
        $actualHasOU = $actualLocation -match "OU="
        
        if (-not $expectedHasOU -and -not $actualHasOU) {
            # Both in domain root, so they're correct
            return @{
                IsCorrect = $true
                ActualLocation = $actualLocation
                ExpectedLocation = $expectedLocation
                DistinguishedName = $actualDN
            }
        }
        
        # Otherwise, compare them directly
        $isCorrectLocation = $actualLocation -eq $expectedLocation
        
        return @{
            IsCorrect = $isCorrectLocation
            ActualLocation = $actualLocation
            ExpectedLocation = $expectedLocation
            DistinguishedName = $actualDN
        }
    } catch {
        Write-Host "  Error retrieving computer with Get-ADComputer: $_" -ForegroundColor Red
        return @{
            IsCorrect = $false
            ActualLocation = "Error"
            ExpectedLocation = $expectedLocation
            DistinguishedName = "Error: $($_)"
        }
    }
}

# Main processing logic
$successCount = 0
$errorCount = 0
$skippedCount = 0
$incorrectLocationCount = 0
$alreadyCorrectCount = 0

if ($computersToProcess.Count -eq 0) {
    Write-Host "No computers found in the current domain to process."
    Stop-Transcript
    exit
}

foreach ($computerEntry in $computersToProcess) {
    $computer = $computerEntry[0]  # Access the first element of the array
    $computerDN = $computer.distinguishedname
    
    # Extract the computer name for AD lookup
    $computerName = $null
    if ($computer.samaccountname -and $computer.samaccountname -match '\$$') {
        # If samAccountName exists and ends with $, use it (removing the trailing $)
        $computerName = $computer.samaccountname -replace '\$$', ''
    } else {
        # Otherwise extract from DN
        try {
            $computerName = ($computerDN -split ',')[0] -replace 'CN=', ''
            Write-Host "  Extracted computer name from DN: $computerName"
        } catch {
            Write-Host "  Could not extract computer name from DN: $_" -ForegroundColor Red
            $errorCount++
            continue
        }
    }
    
    $computerDomain = Get-DomainFromDN -dn $computerDN
    $computerOUPath = Get-OUPathFromDN -dn $computerDN
    
    Write-Host "Processing computer: $($computer.name) ($computerName)"
    Write-Host "  Distinguished Name from file: $computerDN"
    Write-Host "  Domain: $computerDomain"
    Write-Host "  OU Path from file: $computerOUPath"
    
    # Skip computers not in the current domain
    if ($currentDomain -and $computer.domain -ne $currentDomain) {
        Write-Host "  Skipping computer: not in current domain ($currentDomain)" -ForegroundColor Gray
        $skippedCount++
        continue
    }
    
    # Get the expected target location directly from the computer's DN
    $expectedLocation = Get-TargetContainerFromDN -dn $computerDN
    Write-Host "  Expected location from file DN: $expectedLocation"
    
    # Use Get-ADComputer to verify the actual current location of the computer
    $locationVerification = Verify-ComputerLocation -computerName $computerName -expectedLocation $expectedLocation
    
    Write-Host "  Current AD location: $($locationVerification.ActualLocation)"
    Write-Host "  Expected location: $($locationVerification.ExpectedLocation)"
    
    if ($locationVerification.IsCorrect) {
        Write-Host "  Computer is in the correct location according to AD" -ForegroundColor Green
        $alreadyCorrectCount++
        $successCount++
    } else {
        Write-Host "  Computer is NOT in the correct location" -ForegroundColor Yellow
        $incorrectLocationCount++
        
        # Move the computer to the correct location
        try {
            Write-Host "  Moving computer $($computer.name) from $($locationVerification.ActualLocation) to $($locationVerification.ExpectedLocation)" -ForegroundColor Cyan
            
            # Directly use expected location from file
            Move-ADObject -Identity $locationVerification.DistinguishedName -TargetPath $expectedLocation -Confirm:$false
            Write-Host "  Successfully moved computer to correct location" -ForegroundColor Green
            $successCount++
        } catch {
            Write-Host "  Error moving computer: $_" -ForegroundColor Red
            $errorCount++
        }
    }
    
    Write-Host ""
}

# Summary
Write-Host "Configuration complete!"
Write-Host "Successfully processed: $successCount computers"
Write-Host "Already in correct location: $alreadyCorrectCount"
Write-Host "Computers in incorrect locations: $incorrectLocationCount"
Write-Host "Errors encountered: $errorCount computers"
Write-Host "Skipped (not in current domain): $skippedCount computers"

# Stop logging
Stop-Transcript