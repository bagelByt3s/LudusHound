param (
    [Parameter(Mandatory=$true)]
    [string]$f,  # Path to the JSON file
    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all computers will be processed
    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, process all computers
)

# Import the Active Directory module if it's not already loaded
Import-Module ActiveDirectory

# Define the log directory path
$logDirectory = ".\Log\UnconstrainedDelegation_Computer"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\UnconstrainedDelegation_Computer\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "Unconstrained delegation script started at $(Get-Date)"

# Get the current hostname
$currentHostname = $env:COMPUTERNAME
Write-Host "Current hostname: $currentHostname"

# Get the computer object from Active Directory to ensure we have the correct name
try {
    $adComputer = Get-ADComputer -Identity $currentHostname -Properties *
    $samAccountName = $adComputer.SamAccountName
    $computerName = $adComputer.Name
    Write-Host "AD Computer found with Name: $computerName, SAMAccountName: $samAccountName" -ForegroundColor Cyan
}
catch {
    Write-Host "Could not retrieve computer object from Active Directory: $_" -ForegroundColor Red
    Write-Host "Will continue with local hostname: $currentHostname" -ForegroundColor Yellow
    $computerName = $currentHostname
    $samAccountName = "$currentHostname$"
}

# Check if the JSON file exists
if (-not (Test-Path $f)) {
    Write-Error "JSON file not found at: $f"
    Stop-Transcript
    exit 1
}

try {
    # Read and parse the JSON file
    $jsonContent = Get-Content -Path $f | ConvertFrom-Json
    
    # Flag to track if we found our computer in the JSON
    $foundCurrentHost = $false
    $unconstrainedDelegationConfigured = $false
    
    # Process the JSON content
    foreach ($computerArray in $jsonContent) {
        foreach ($computerObj in $computerArray) {
            # Compare using multiple possible identifiers
            if (
                $computerObj.name -eq $computerName -or 
                $computerObj.name -eq $currentHostname -or
                $computerObj.samaccountname -eq $samAccountName
            ) {
                $foundCurrentHost = $true
                $matchedName = $computerObj.name
                Write-Host "Found current computer in JSON file as: $matchedName" -ForegroundColor Cyan
                
                # Check if unconstrained delegation is set to true
                if ($computerObj.unconstraineddelegation -eq $true) {
                    Write-Host "Setting unconstrained delegation for current computer: $matchedName" -ForegroundColor Green
                    
                    # Set unconstrained delegation using the AD cmdlet
                    try {
                        # Set the TrustedForDelegation property to true
                        Set-ADComputer $computerName -TrustedForDelegation $true
                        Write-Host "Successfully configured unconstrained delegation on $computerName" -ForegroundColor Green
                        $unconstrainedDelegationConfigured = $true
                    }
                    catch {
                        Write-Host "Failed to set unconstrained delegation on $computerName : $_" -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Current computer $matchedName does not have unconstrained delegation set to true in the configuration file." -ForegroundColor Yellow
                }
                
                # We found our computer, no need to continue searching
                break
            }
        }
        
        # If we found the computer, exit the outer loop as well
        if ($foundCurrentHost) {
            break
        }
    }
    
    # If we didn't find our computer in the JSON
    if (-not $foundCurrentHost) {
        Write-Host "Current computer not found in the JSON configuration file. Tried names: $computerName, $currentHostname, $samAccountName" -ForegroundColor Yellow
    }
    
    # Summary
    if ($unconstrainedDelegationConfigured) {
        Write-Host "Summary: Unconstrained delegation was successfully configured on $computerName" -ForegroundColor Green
    } else {
        Write-Host "Summary: No changes were made to unconstrained delegation settings on $computerName" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Error processing JSON file: $_"
    Stop-Transcript
    exit 1
}

# Log the end of the script
Write-Host "Unconstrained delegation script completed at $(Get-Date)"
Stop-Transcript