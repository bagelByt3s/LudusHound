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
$logDirectory = ".\Log\OUs"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\OUs\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "OU creation script started at $(Get-Date)"
Write-Host ""

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json

# Flatten the JSON structure if needed (assuming it's an array of arrays)
$ous = $jsonContent | ForEach-Object { $_[0] }

# Determine which OUs to process
if ($fullSend) {
    # If fullSend is specified, process all users
    $ousToProcess = $ous
} else {
    # Otherwise, process a limited number based on $c
    if ($c -eq 0) {
        $ousToProcess = $ous  # Process all OUs if $c is 0
    } else {
        $ousToProcess = $ous[0..($c - 1)]  # Process only the first $c OUs
    }
}

# Iterate over the selected OUs
foreach ($ou in $ousToProcess) {
    # Extract necessary OU details
    $name = $ou.name
    $path = $ou.distinguishedname

    # Clean up name (remove anything after '@' if it's part of an email)
    $name = $name -replace "@.*", ""

    #Write-Host "Processing OU: $name"
    #Write-Host "Path: $path"

    # Extract the base domain from the Distinguished Name (all the DC parts)
    # Example: "DC=PHANTOM,DC=CORP" or "DC=child,DC=domain,DC=local"
    # Split the path by commas into an array
    $splitPath = $path -split ','

    # Filter the parts that start with "DC="
    $dcParts = $splitPath | Where-Object { $_ -like "DC=*" }
    
    # Filter the parts that start with "OU=" This will be iterated over to create the OU's and accounts for the creation of nested OUs
    $ouParts = $splitPath | Where-Object { $_ -like "OU=*" } 

    [Array]::Reverse($ouParts)

    # Join the filtered "DC=" parts with commas
    # Example DC=PHANTOM,DC=CORP
    $basePath = $dcParts -join ','

    # Initialize current path as the base path
    $currentPath = $basePath

    

    # Create OUs step by step based on the path
    foreach ($ou in $ouParts) {
        # Extract the OU name from each part
        $ouName = $ou -replace '^OU=', ''

        # Check if the OU exists in the current path

        $futurePath = "OU=$ouName" + "," + $currentPath
        echo "Working on OU: $futurePath"
        $existingOU =  Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $futurePath} 
         
        if (-not $existingOU) {
            # If the OU does not exist, create it
            Write-Host "Creating OU: $ouName at $currentPath"
            New-ADOrganizationalUnit -Name $ouName -Path $currentPath -errorAction SilentlyContinue
        } else {
            Write-Host "OU: $ouName already exists at $currentPath"
            write-host ""
        }

        # Update currentPath for the next iteration
        $currentPath = "OU=$ouName,$currentPath"
    }
}
Write-Host ""   
# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "OU creation script ended at $(Get-Date)"