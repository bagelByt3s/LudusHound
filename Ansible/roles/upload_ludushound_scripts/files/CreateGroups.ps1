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
$logDirectory = ".\Log\Groups"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\Groups\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "Group creation script started at $(Get-Date)"

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json

# Flatten the JSON structure if needed (assuming it's an array of arrays)
$groups = $jsonContent | ForEach-Object { $_[0] }

# Determine which groups to process
if ($fullSend) {
    # If fullSend is specified, process all groups
    $groupsToProcess = $groups
} else {
    # Otherwise, process a limited number based on $c
    if ($c -eq 0) {
        $groupsToProcess = $groups  # Process all groups if $c is 0
    } else {
        $groupsToProcess = $groups[0..($c - 1)]  # Process only the first $c groups
    }
}

# Iterate over the selected users
foreach ($group in $groupsToProcess) {
    # Extract necessary group details

    $domain = $group.domain
    $name = $group.name
    $name = $name.Split('@')[0]
    $distinguishedname = $group.distinguishedname
    $domainsid = $group.domainsid
    $samaccountname = $group.samaccountname
    $isaclprotected = $group.itsaclprotected
    $description = $group.description
    $whencreated = $group.whencreated
    $admincount = $group.admincount

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
                        -GroupScope DomainLocal  # Adjust scope as necessary (e.g., DomainLocal, Global, Universal)
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
