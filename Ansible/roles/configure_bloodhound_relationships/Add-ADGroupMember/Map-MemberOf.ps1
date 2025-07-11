param (
    [Parameter(Mandatory=$true)]
    [string]$f,

    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all users will be processed

    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, create all users
)

# Import the Active Directory module if it's not already loaded
Import-Module ActiveDirectory

# Define the log directory path
$logDirectory = "..\.\Logs"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "Member of script started at $(Get-Date)"

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | ConvertFrom-Json

#echo $jsonContent

# Determine which users to process
if ($fullSend) {
    # If fullSend is specified, process all users
    echo "full send"
    $entriesToProcess = $jsonContent
} else {
    # Otherwise, process a limited number based on $c
    echo "not full send"
    $entriesToProcess = if ($c -eq 0) { $jsonContent } else { $jsonContent.data[0..($c-1)] }
}

echo "item count $($entriesToProcess.Count)"

# Iterate over the selected users
for ($i=0; $i -le $entriesToProcess.Count; $i++) {
    $memberOfEntry = $entriesToProcess[$i]
    $properties = $memberOfEntry

    # Extract necessary user details
    $userName = $properties.source
    $groupName = $properties.target

    if($userName -match "@")
    {
        $userName = ($userName -split "@")[0]
    }
    if($groupName -match "@")
    {
        $groupName = ($groupName -split "@")[0]
    }

    echo "Processing user: $userName"
    echo "Processing Group: $groupName"

    # Check if the user already exists in group (optional, you can modify this check)
    $alreadyInGroup = Get-ADGroupMember -Identity $groupName | Where-Object {$_.name -eq $userName} -ErrorAction SilentlyContinue
    if ($alreadyInGroup) {
        Write-Host "User $userName already in group. Skipping creation."
    }
    else {
        # Add Member to Group
        Add-ADGroupMember -Identity $groupName -Members $userName         
        echo "User $userName added to group $groupName successfully."
    }
    
    Write-Host "------------------------------------------------------------------------------"
}

# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "Map-MemberOf script ended at $(Get-Date)"
