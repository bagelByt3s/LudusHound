param(
    [string]$f,         # File path
    [int]$c = 0,        # Count of entries to process (0 means all entries)
    [switch]$fullSend   # Full send flag (process all entries)
)
# Check if the file path is provided
if (-not $f) {
    Write-Host "Please provide the path to the JSON file using the -f argument."
    exit
}
# Check if the file exists
if (-not (Test-Path $f)) {
    Write-Host "The file '$f' does not exist."
    exit
}
# Create the Log directory if it doesn't exist
$logDir = ".\Log\LocalMembersOf"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}
# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"
# Read and parse the JSON file
try {
    $jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json
} catch {
    Write-Host "Failed to parse the JSON file. Please check the file format."
    exit
}
# Determine how many entries to process
if ($fullSend) {
    # If -fullSend is provided, process all entries
    $jsonContent = $jsonContent
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $jsonContent = $jsonContent[0..($c - 1)]  # Get the first $c entries
}
# Start logging to the log file
Start-Transcript -Path $logFile

# Get the computer's hostname
$computerHostname = $env:COMPUTERNAME

# Iterate through each object in the JSON array, log source and target
foreach ($entry in $jsonContent) {
    $source = $($entry.source)
    $sourceShortName = $source.Split('@')[0]
    $sourceDomain = $($entry.sourceDomain)
    
    $target = $($entry.target)
    $targetShortName = $target.split('@')[0]
    $targetGroup = $target.Split('@')[1]
    $hostname = $targetGroup.Split('.')[0]

    
    # Check if computer hostname matches the hostname variable
    if ($computerHostname.ToUpper() -eq $hostname.ToUpper()) {

	

       if ($targetShortName.ToUpper() -ne "USERS".ToUpper()) {

	     if ($sourceShortName.ToUpper() -ne "DOMAIN ADMINS".ToUpper()) {
                	Write-Host "Hostname matches: $computerHostname matches Target Computer Entry: $hostname" -ForegroundColor Green
			echo "Adding $source to local group: $target"

			Add-LocalGroupMember -Group "$targetShortName" -Member "$source"
        	        #echo "SourceShortname $sourceShortName "
               	 	#echo "sourceDomain $sourceDomain "
                	#echo ""
                	#echo "target $target"
               	 	#echo "targetShortName $targetShortName"
                	#echo "target domain $targetGroup"

            }
        }
    }


    
    
   # $logLine = "Source: $source, Target: $target"
    
    # Print to console
    Write-Host $logLine
    
}
# End the logging
Stop-Transcript
# Inform the user about the log file location
Write-Host "Log file created at: $logFile"