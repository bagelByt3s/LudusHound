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
$logDirectory = ".\Log\Containers"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\Containers\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "Container creation script started at $(Get-Date)"
Write-Host ""

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json



# Flatten the JSON structure if needed (assuming it's an array of arrays)
$Containers = $jsonContent | ForEach-Object { $_[0] }

# Determine which Containers to process
if ($fullSend) {
    # If fullSend is specified, process all users
    $ContainersToProcess = $Containers
} else {
    # Otherwise, process a limited number based on $c
    if ($c -eq 0) {
        $ContainersToProcess = $Containers  # Process all Containers if $c is 0
    } else {
        $ContainersToProcess = $Containers[0..($c - 1)]  # Process only the first $c Containers
    }
}

# Iterate over the selected Containers
foreach ($Container in $ContainersToProcess) {
    # Extract necessary Container details
    $name = $Container.name
    $path = $Container.distinguishedname

    # Clean up name (remove anything after '@' if it's part of an email)
    $name = $name -replace "@.*", ""

    #Write-Host "Processing Container: $name"
    #Write-Host "Path: $path"

    # Extract the base domain from the Distinguished Name (all the DC parts)
    # Example: "DC=PHANTOM,DC=CORP" or "DC=child,DC=domain,DC=local"
    # Split the path by commas into an array
    $splitPath = $path -split ','

    # Filter the parts that start with "DC="
    $dcParts = $splitPath | Where-Object { $_ -like "DC=*" }
    
    # Filter the parts that start with "CN=" This will be iterated over to create the Container's and accContainernts for the creation of nested Containers
    $ContainerParts = $splitPath | Where-Object { $_ -like "CN=*" } 

    

    [Array]::Reverse($ContainerParts)

    # Join the filtered "DC=" parts with commas
    # Example DC=PHANTOM,DC=CORP
    $basePath = $dcParts -join ','

    # Initialize current path as the base path
    $currentPath = $basePath

    

    # Create Containers step by step based on the path
    foreach ($Container in $ContainerParts) {
        # Extract the Container name from each part
        $ContainerName = $Container -replace '^CN=', ''

        # Check if the Container exists in the current path

        $futurePath = "CN=$ContainerName" + "," + $currentPath
        echo "Working on Container: $futurePath"
<#
        if ($futurePath -like "*CN=CONFIGURATION*") {

            $searchBase = "CN=CONFIGURATION,$basePath"
	    $searchBase = '"' + $searchBase + '"'
            $existingContainer = Get-ADObject -Filter {CN -eq $ContainerName} -SearchBase $searchBase
		echo "Hello"


        } else {

            $existingContainer =  Get-ADObject -Filter {DistinguishedName -eq $futurePath} 
        }

 #>
# Example: CN=CONFIGURATION,DC=WRAITH,DC=CORP // Don't create container, this is a default container


	# Check if container exists allready
	$existingContainer = Get-ADObject -Filter {CN -eq $ContainerName} -SearchBase $currentPath

	# Get the value of CN=CONTAINER,DC=DOMAIN,DC=CORP. If this is the container, then we do not want to create it (Created by default allready 	 
        $ConfigurationBasePath =  "CN=CONFIGURATION," + $basePath

 	#If the container does not exist, and the container is not CN=CONTAINER,DC=DOMAIN,DC=CORP then create container
        if (-not $existingContainer -and $futurePath -ne $ConfigurationBasePath) {
            # If the Container does not exist, create it
            Write-Host "Creating Container: $ContainerName at $currentPath"
            
            New-AdObject -Name "$ContainerName" -type container -Path "$currentPath"
            Write-Host "Created $futurePath"
            Write-Host ""
        } else {
            Write-Host "Container: $ContainerName already exists at $currentPath"
            write-host ""
        }

        # Update currentPath for the next iteration
        $currentPath = "CN=$ContainerName,$currentPath"
    }
}
Write-Host ""   
# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "Container creation script ended at $(Get-Date)"