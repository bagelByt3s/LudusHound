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
$logDirectory = ".\Log\GPOS"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\GPOS\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "GPO creation script started at $(Get-Date)"

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json

# Flatten the JSON structure if needed (assuming it's an array of arrays)
$gpos = $jsonContent | ForEach-Object { $_[0] }

# Determine which GPOS to process
if ($fullSend) {
    # If fullSend is specified, process all GPOs
    $gposToProcess = $gpos
} else {
    # Otherwise, process a limited number based on $c
    if ($c -eq 0) {
        $gposToProcess = $gpos  # Process all GPOs if $c is 0
    } else {
        $gposToProcess = $gpos[0..($c - 1)]  # Process only the first $c GPOs
    }
}

# Iterate over the selected GPOs
foreach ($gpo in $gposToProcess) {
    # Extract necessary user details
    $name = $gpo.name
    # Remove the domain part using regex
    $name = $name -replace "@.*", ""
 
    Write-Host "Processing GPO: $name"

    # Check if the gpo already exists (optional, you can modify this check)
    $existingGpo = Get-GPO -Name $name -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Host "GPO $gpoName already exists. Skipping creation."
    }
    else {
        # Create the new GPO
        New-GPO -Name $name
	
        Write-Host "GPO $gpoName created successfully."
    }
    
    Write-Host "------------------------------------------------------------------------------"
}


# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "GPO creation script ended at $(Get-Date)"