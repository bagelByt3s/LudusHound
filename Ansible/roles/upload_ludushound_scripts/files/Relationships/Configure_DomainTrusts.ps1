##Configure_DomainTrusts.ps1

param(
    [string]$f,         # File path
    [int]$c = 0,        # Count of entries to process (0 means all entries)
    [switch]$fullSend   # Full send flag (process all entries)
)

# powershell -ep bypass c:\windows\tasks\LudusHound\Scripts\Relationships\Configure_DomainTrusts.ps1 -f C:\windows\tasks\Ludushound\Relationships\DomainTrusts.json -fullSend
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
$logDir = ".\Log\DomainTrusts"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"
Start-Transcript -Path $logFile
echo ""

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

# Start logging
$logContent = "Log Started: $(Get-Date)" + "`r`n"
$logContent += "Processing file: $f" + "`r`n`r`n"

$sourceDomainIP = ""
$targetDomainIP = ""




# Iterate through each object in the JSON array, log source and target
foreach ($entry in $jsonContent) {

    if ($entry.TrustType -ne "ParentChild") {

        $sourceDomain = $($entry.SourceDomain)
        $targetDomain = $($entry.TargetDomain)
        $trustType = $($entry.TrustType)

        echo "Source Domain: $sourceDomain"
        echo "Target Domain: $targetDomain"
        echo "Trust Type: $trustType"
        echo ""

        Write-Host "$sourceDomain is trusted by $targetDomain"
        echo "Checking if trust is unidirectional or bidirecitonal"
        $isBiDirectional = $false

        $jsonContentFull = Get-Content -Path "c:\windows\tasks\ludushound\relationships\DomainTrusts.json" | Out-String | ConvertFrom-Json

        foreach ($directionCheck_Entry in $jsonContentFull) {
        
            $directionCheck_SourceDomain = $($directionCheck_Entry.SourceDomain)
            $directionCheck_TargetDomain = $($directionCheck_Entry.TargetDomain)

        

            if ($sourceDomain -eq $directionCheck_TargetDomain -and $targetDomain -eq $directionCheck_SourceDomain) {
                Write-Host "$sourceDomain has bidirectional trust with $targetDomain"
                echo ""
                $isBiDirectional = $true
            }

        }

        

        # Configure two way domain trust if isBidirecitonal is true 
        if ($isBidirectional -eq $true) {
            Write-Host "Configuring bidirectional trust between $sourceDomain and $targetDomain"
            
            # Use double quotes to ensure variables are expanded properly
            #netdom trust "$sourceDomain" /d:"$targetDomain" /add /twoway /realm /userD:"domainadmin@$sourceDomain" /passwordD:"password"

            netdom trust "$sourceDomain" /domain:"$targetDomain" /add /twoway /userD:"$targetDomain\domainadmin" /passwordD:"password"

            Start-Sleep -Seconds 5

            netdom trust "$sourceDomain" /domain:"$targetDomain" /quarantine:no
        }


        # Configure one way domain trust if isBidirecitonal is false
        if ($isBidirectional -eq $false ) {

            if ((Get-WmiObject Win32_ComputerSystem).Domain -eq $sourceDomain) {

                Write-Host "Configuring one-way trust between $sourceDomain and $targetDomain"

                #netdom trust $sourceDomain /d:$targetDomain /add  /realm /userD:domainadmin@$sourceDomain /passwordD:password

                netdom trust "$sourceDomain" /domain:"$targetDomain" /add  /userD:"$targetDomain\domainadmin" /passwordD:"password"

                Start-Sleep -Seconds 5

                netdom trust "$sourceDomain" /domain:"$targetDomain" /quarantine:no
            } else {

                Write-Host Write-Host "$sourceDomain is not the domain for this DC, skipping"
            }
        }

        # Turn it back to false for the next domain 
        $isBidirectional -eq $false

    
        
        # Append to log content
        $logContent += $logLine + "`r`n"

    }
}

# End the logging
Stop-Transcript

