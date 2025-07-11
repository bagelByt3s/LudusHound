param (
    [Parameter(Mandatory=$true)]
    [string]$f,  # Path to the JSON file
    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all users will be processed
    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, create all users
)
# Import the Active Directory module if it's not already loaded
Import-Module ActiveDirectory
# Define the log directory path
$logDirectory = ".\Log\Computers"
# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}
# Define the log file path with a timestamp
$logPath = ".\Log\Computers\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
# Start logging to the log file
Start-Transcript -Path $logPath
# Log the start of the script
Write-Host "User creation script started at $(Get-Date)"

# Path to the computerIPConfig.json file
$ipConfigPath = "c:\windows\tasks\ludushound\computerIPConfig.json"

# Read and parse the computerIPConfig.json file if it exists
$hostsToSkip = @()
if (Test-Path -Path $ipConfigPath) {
    Write-Host "Reading computerIPConfig.json file to identify systems to skip..."
    $ipConfigContent = Get-Content -Path $ipConfigPath | ConvertFrom-Json
    
    if ($ipConfigContent.systems) {
        # Extract all hostnames from the computerIPConfig.json file
        $hostsToSkip = $ipConfigContent.systems | ForEach-Object { $_.hostname }
        Write-Host "Found $(($hostsToSkip).Count) systems to check against in computerIPConfig.json"
    } else {
        Write-Host "No systems found in computerIPConfig.json"
    }
} else {
    Write-Host "Warning: computerIPConfig.json file not found at $ipConfigPath" -ForegroundColor Yellow
}

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json
# Flatten the JSON structure if needed (assuming it's an array of arrays)
$computers = $jsonContent | ForEach-Object { $_[0] }
# Determine which computers to process
if ($fullSend) {
    # If fullSend is specified, process all computers
    $computersToProcess = $computers
} else {
    # Otherwise, process a limited number based on $c
    if ($c -eq 0) {
        $computersToProcess = $computers  # Process all computers if $c is 0
    } else {
        $computersToProcess = $computers[0..($c - 1)]  # Process only the first $c computers
    }
}
# Iterate over the selected users
foreach ($computer in $computersToProcess) {


# Extract necessary computer details
$fullName = $computer.name
# Extract the base hostname without domain
if ($fullName -like "*.*") {
    # If name contains periods, take the first part as the hostname
    $name = $fullName.Split('.')[0]
} else {
    # If no periods, use the full name as is
    $name = $fullName
}

# Check if either the full name or base name exists in the skip list
if ($hostsToSkip -contains $baseName -or $hostsToSkip -contains $fullName) {
    Write-Host "Computer $fullName (base name: $baseName) exists in computerIPConfig.json. Skipping creation." -ForegroundColor Yellow
    Write-Host "------------------------------------------------------------------------------"
    continue
}


    $distinguishedName = $computer.distinguishedname
    $haslaps = $computer.haslaps
    $enabled = $computer.enabled
    $unconstraineddelegation = $computer.unconstraineddelegation
    $operatingsystem = $computer.operatingsystem
    $samaccountname = $computer.samaccountname
    Write-Host "Processing computer: $name"
    
    # Check if the computer already exists in computerIPConfig.json
    if ($hostsToSkip -contains $name) {
        Write-Host "Computer $name exists in computerIPConfig.json. Skipping creation." -ForegroundColor Yellow
        Write-Host "------------------------------------------------------------------------------"
        continue
    }
    
    # Check if the computer already exists in Active Directory
    $ifSamAccountNameExists = Get-ADComputer -Filter {Name -eq $name} -ErrorAction SilentlyContinue
    $ifNameExists =  Get-ADComputer -Filter {Name -eq $samaccountname} -ErrorAction SilentlyContinue
    $SamAccountNameNoDollar = $samaccountname -replace '\$', ''
    $ifSamAccountNameNoDollarExists =  Get-ADComputer -Filter {Name -eq $SamAccountNameNoDollar} -ErrorAction SilentlyContinue
    
    if ($ifSamAccountNameExists -or $ifNameExists -or $ifSamAccountNameNoDollarExists) {
        Write-Host "Computer $name already exists in Active Directory. Skipping creation."
    }
    else {
        # If the computer does not exist, create it
        New-ADComputer -Name $name `
                       -SamAccountName $samaccountname `
                       -Enabled $enabled `
                       -OperatingSystem $operatingsystem `
                       -AccountPassword (ConvertTo-SecureString "password" -AsPlainText -Force) `
                       -PassThru `
                       -dnshostname $name
                       
        Write-Host "Computer $name created successfully."

        if ($unconstraineddelegation) {
            Write-Host "$name is configured for Unconstrained delegation, configuring"
            sleep 3 
            Set-ADComputer $name -TrustedForDelegation $true
        }
    }
    Write-Host "------------------------------------------------------------------------------"
}
# End the logging
Stop-Transcript
# Log the end of the script
Write-Host "Computer creation script ended at $(Get-Date)"