param (
    [Parameter(Mandatory=$true)]
    [string]$f,

    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all computers will be processed

    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, create all computers
)

# Import the Active Directory module if it's not already loaded
Import-Module ActiveDirectory

# Define the log directory path
$logDirectory = ".\Log"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "Computer creation script started at $(Get-Date)"

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json

# Determine which computers to process
if ($fullSend) {
    # If fullSend is specified, process all computer
    $computersToProcess = $jsonContent.data
} else {
    # Otherwise, process a limited number based on $c
    $computersToProcess = if ($c -eq 0) { $jsonContent.data } else { $jsonContent.data[0..($c-1)] }
}

# Iterate over the selected computers
foreach ($computer in $computersToProcess) {
    $properties = $computer.Properties
    #Extract necessary computer details 

    $name = $properties.name
    $distinguishedName = $properties.distinguishedname
    $haslaps = $properties.haslaps
    $enabled = $properties.enabled
    $unconstraineddelegation = $properties.unconstraineddelegation
    $operatingsystem = $properties.operatingsystem
    $samaccountname = $properties.samaccountname
    
    
    Write-Host "Processing computer: $name"
    
    # Check if the computer already exists in Active Directory
    $ifSamAccountNameExists = Get-ADComputer -Filter {Name -eq $name} -ErrorAction SilentlyContinue
    $ifNameExists =  Get-ADComputer -Filter {Name -eq $samaccountname} -ErrorAction SilentlyContinue
    $SamAccountNameNoDollar = $samaccountname -replace '\$', ''
    $ifSamAccountNameNoDollarExists =  Get-ADComputer -Filter {Name -eq $SamAccountNameNoDollar} -ErrorAction SilentlyContinue
    
    if ($ifSamAccountNameExists -or $ifNameExists -or $ifSamAccountNameNoDollarExists ) {
        Write-Host "Computer $name already exists. Skipping creation."
    }
    else {
        # If the computer does not exist, create it
        New-ADComputer -Name $samaccountname `
                       -SamAccountName $samaccountname `
                       -Enabled $enabled `
                       -OperatingSystem $operatingsystem `
                       -AccountPassword (ConvertTo-SecureString "password" -AsPlainText -Force) `
                       -PassThru `
                       -dnshostname $name `
                       
                       
        Write-Host "Computer $name created successfully."
    }


    Write-Host "------------------------------------------------------------------------------"
}

# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "Computer creation script ended at $(Get-Date)"
