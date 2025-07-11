param (
    [Parameter(Mandatory=$true)]
    [string]$f,

    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all groups will be processed

    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, create all groups
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
Write-Host "Group creation script started at $(Get-Date)"

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json

# Determine which groups to process
if ($fullSend) {
    # If fullSend is specified, process all groups
    $groupsToProcess = $jsonContent.data
} else {
    # Otherwise, process a limited number based on $c
    $groupsToProcess = if ($c -eq 0) { $jsonContent.data } else { $jsonContent.data[0..($c-1)] }
}

# Iterate over the selected groups
foreach ($group in $groupsToProcess) {
    $properties = $group.Properties
    #Extract necessary group details 

    $domain = $properties.domain
    $name = $properties.name
    $distinguishedname = $properties.distinguishedname
    $domainsid = $properties.domainsid
    $samaccountname = $properties.samaccountname
    $isaclprotected = $properties.itsaclprotected
    $description = $properties.description
    $whencreated = $properties.whencreated
    $admincount = $properties.admincount

    # Check if samAccountName is empty or null, and skip if so
    if (-not $samaccountname) {
        Write-Host "samAccountName is empty. Skipping group creation."
    } else {
        # Check if the group already exists
        $existingGroup = Get-ADGroup -Filter {SamAccountName -eq $samaccountname} -ErrorAction SilentlyContinue
        
        if ($existingGroup) {
            Write-Host "Group with samAccountName '$samaccountname' already exists. Skipping creation."
        } else {
            # Create the new group
            New-ADGroup -Name $name `
                        -Description $description `
                        -SamAccountName $samaccountname `
                        -PassThru `
                        -GroupScope Global  # Adjust scope as necessary (e.g., DomainLocal, Global, Universal)
                        # -Path $distinguishedname ` Gets error with this because calling some objects that don't exist

            Write-Host "Processing group: $name"
        }
    }
        
        
        Write-Host "------------------------------------------------------------------------------"
}

# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "Group creation script ended at $(Get-Date)"
