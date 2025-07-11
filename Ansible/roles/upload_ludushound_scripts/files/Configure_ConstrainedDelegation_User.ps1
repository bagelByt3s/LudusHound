param (
    [Parameter(Mandatory=$true)]
    [string]$f,  # Path to the JSON file
    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all users will be processed
    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, process all users
)

# Import the Active Directory module if it's not already loaded
Import-Module ActiveDirectory

# Define the log directory path
$logDirectory = ".\Log\ConstrainedDelegation_Users"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory | Out-Null
}

# Define the log file path with a timestamp
$logPath = ".\Log\ConstrainedDelegation_Users\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "Delegation permissions script started at $(Get-Date)"

# Check if the JSON file exists
if (-not (Test-Path $f)) {
    Write-Error "JSON file not found at: $f"
    Stop-Transcript
    exit 1
}

try {
    # Read and parse the JSON file
    $jsonContent = Get-Content -Path $f | ConvertFrom-Json

    # Determine which users to process
    if ($fullSend) {
        # If fullSend is specified, process all users
        $usersToProcess = $jsonContent
    } else {
        # Otherwise, process a limited number based on $c
        if ($c -eq 0) {
            $usersToProcess = $jsonContent  # Process all users if $c is 0
        } else {
            # Process only the first $c users or arrays
            $usersToProcess = $jsonContent[0..([Math]::Min($c - 1, $jsonContent.Count - 1))]
        }
    }

    # Counter for tracking processed users
    $processedCount = 0
    $updatedCount = 0

    # Process each user in the flattened array
    foreach ($userArray in $usersToProcess) {
        foreach ($userObj in $userArray) {
            $samAccountName = $userObj.samaccountname
            Write-Host "Processing user: $samAccountName" -ForegroundColor Cyan

            # Check if trustedtoauth is set to true
            if ($userObj.trustedtoauth -eq $true) {
                Write-Host "User $samAccountName has trustedtoauth set to true" -ForegroundColor Green

                # Check if there are SPNs in the allowedtodelegate array
                if ($userObj.allowedtodelegate -and $userObj.allowedtodelegate.Count -gt 0) {
                    $delegationTargets = $userObj.allowedtodelegate
                    Write-Host "Found delegation targets: $($delegationTargets -join ', ')" -ForegroundColor Green

                    try {
                        # Get current delegations
                        $user = Get-ADUser -Identity $samAccountName -Properties "msDS-AllowedToDelegateTo"
                        $currentDelegations = $user.'msDS-AllowedToDelegateTo'
                        
                        # Track if any changes were made
                        $delegationsAdded = $false
                        
                        # Add new delegations that don't already exist
                        foreach ($target in $delegationTargets) {
                            if ($currentDelegations -notcontains $target) {
                                Write-Host "Adding delegation permission for $target" -ForegroundColor Green
                                if ($null -eq $currentDelegations) {
                                    $currentDelegations = @($target)
                                } else {
                                    $currentDelegations += $target
                                }
                                $delegationsAdded = $true
                            } else {
                                Write-Host "Delegation permission for $target already exists" -ForegroundColor Yellow
                            }
                        }
                        
                        # Update AD user if changes were made
                        if ($delegationsAdded) {
                            Set-ADUser -Identity $samAccountName -Replace @{
                                "msDS-AllowedToDelegateTo" = $currentDelegations
                            }
                            
                            # Ensure TrustedToAuthForDelegation is set
                            Set-ADAccountControl -Identity $samAccountName -TrustedToAuthForDelegation $true
                            
                            Write-Host "Successfully configured delegation permissions for $samAccountName" -ForegroundColor Green
                            $updatedCount++
                        }
                    }
                    catch {
                        Write-Host "Failed to configure delegation permissions for $samAccountName`: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "User $samAccountName has no SPNs in allowedtodelegate array" -ForegroundColor Yellow
                }
            } else {
                Write-Host "User $samAccountName does not have trustedtoauth set to true, skipping" -ForegroundColor Yellow
            }

            $processedCount++
        }
    }

    # Log summary
    Write-Host "Total users processed: $processedCount" -ForegroundColor Cyan
    Write-Host "Users updated with delegation permissions: $updatedCount" -ForegroundColor Green
}
catch {
    Write-Error "Error processing JSON file: $_"
    Stop-Transcript
    exit 1
}

# Log the end of the script
Write-Host "Delegation permissions script completed at $(Get-Date)"
Stop-Transcript