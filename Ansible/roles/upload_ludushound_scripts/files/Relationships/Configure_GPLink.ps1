param(
    [Parameter(Position=0)]
    [Alias("f")]
    [string]$GPLinkFile,      # File path for GPlink.json
    
    [Parameter(Position=1)]
    [int]$c = 0,              # Count of entries to process (0 means all entries)
    
    [Parameter(Position=2)]
    [Alias("full")]
    [switch]$fullSend         # Full send flag (process all entries)
)

# Check if the file path is provided
if (-not $GPLinkFile) {
    Write-Host "Please provide the path to the GPLink JSON file using the -GPLinkFile or -f argument."
    exit
}

# Check if the file exists
if (-not (Test-Path $GPLinkFile)) {
    Write-Host "The file '$GPLinkFile' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\Configure_Relationship_GPLINK"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Start logging to the log file
Start-Transcript -Path $logFile

# Import required module
Import-Module GroupPolicy

# Read the JSON file
$gpLinks = Get-Content -Path $GPLinkFile -Raw | ConvertFrom-Json

# Check if JSON file was loaded successfully
if (-not $gpLinks) {
    Write-Error "Failed to load GPLink JSON file. Please check the file path and content."
    Stop-Transcript
    exit 1
}

# Create a hashtable to track processed links to avoid duplicates
$processedLinks = @{}

# Initialize counters
$totalLinks = 0
$successLinks = 0
$skippedDuplicates = 0
$failedLinks = 0

# Determine how many entries to process
$totalEntries = $gpLinks.Count
$entriesToProcess = if ($c -eq 0 -or $fullSend) { $totalEntries } else { [Math]::Min($c, $totalEntries) }

Write-Host "Processing $entriesToProcess of $totalEntries GPLink entries..."

# Process each GPLink entry
for ($i = 0; $i -lt $entriesToProcess; $i++) {
    $link = $gpLinks[$i]
    $totalLinks++
    
    # Extract GPO name and domain from the source field
    $gpoInfo = $link.source -split '@'
    $gpoName = $gpoInfo[0].Trim()
    
    # Extract target OU or domain
    $targetInfo = $link.target -split '@'
    $targetName = $targetInfo[0].Trim()
    $targetDomain = $link.targetDomain
    
    # Create a unique key to identify this link
    $linkKey = "$($gpoName)_$($targetName)"
    
    # Skip if this is a duplicate
    if ($processedLinks.ContainsKey($linkKey)) {
        Write-Host "Skipping duplicate link for GPO '$gpoName' to target '$targetName'" -ForegroundColor Yellow
        $skippedDuplicates++
        continue
    }
    
    # Mark this link as processed
    $processedLinks[$linkKey] = $true
    
    # Use the targetDN from the JSON if available, otherwise fallback to the old method
    if ($link.PSObject.Properties.Name -contains "targetDN" -and $link.targetDN) {
        $targetPath = $link.targetDN
        Write-Host "Using provided targetDN: $targetPath" -ForegroundColor Cyan
    } else {
        # Determine if target is an OU or domain (fallback method)
        $targetPath = ""
        if ($targetName -eq $targetDomain) {
            # This is a domain link
            $targetPath = "DC=" + ($targetDomain -replace "\.", ",DC=")
            Write-Host "Using domain targetPath: $targetPath" -ForegroundColor Yellow
        } else {
            # This is an OU link - first try to find the actual OU path
            try {
                # Get the actual OU path from Active Directory
                $domainDN = "DC=" + ($targetDomain -replace "\.", ",DC=")
                $ouObjects = Get-ADOrganizationalUnit -Filter "Name -eq '$targetName'" -ErrorAction Stop | 
                    Where-Object { $_.DistinguishedName -like "*$domainDN" }
                
                # Check if we found any matching OUs
                if ($ouObjects -and $ouObjects.Count -gt 0) {
                    # If multiple OUs with the same name exist, we need to handle that
                    if ($ouObjects.Count -gt 1) {
                        Write-Host "Found multiple OUs with name '$targetName'. Using the most specific match." -ForegroundColor Yellow
                        
                        # Try to identify the correct OU - first look for one that matches any source info we have
                        $sourceOU = $null
                        
                        # Look for OU path hints in the target field (sometimes target has format like "EAST/USERS")
                        if ($link.target -like "*/*") {
                            $pathParts = $link.target -split '/' | Where-Object { $_ -ne $targetDomain }
                            
                            foreach ($ou in $ouObjects) {
                                $matchScore = 0
                                foreach ($part in $pathParts) {
                                    if ($ou.DistinguishedName -like "*OU=$part,*") {
                                        $matchScore++
                                    }
                                }
                                
                                if ($matchScore -gt 0) {
                                    $sourceOU = $ou
                                    Write-Host "Selected OU based on path match: $($ou.DistinguishedName)" -ForegroundColor Cyan
                                    break
                                }
                            }
                        }
                        
                        # If we still don't have a match, use the OU with the deepest nesting
                        if (-not $sourceOU) {
                            $sourceOU = $ouObjects | 
                                Sort-Object { ($_.DistinguishedName -split ',').Count } -Descending | 
                                Select-Object -First 1
                            Write-Host "Selected the most deeply nested OU: $($sourceOU.DistinguishedName)" -ForegroundColor Cyan
                        }
                        
                        $targetPath = $sourceOU.DistinguishedName
                    } else {
                        # Just use the single match
                        $targetPath = $ouObjects[0].DistinguishedName
                        Write-Host "Found OU path: $targetPath" -ForegroundColor Cyan
                    }
                } else {
                    # Fall back to the simple path if no matching OU is found
                    Write-Host "No matching OU found for '$targetName', using default path construction" -ForegroundColor Yellow
                    $targetPath = "OU=$targetName,DC=" + ($targetDomain -replace "\.", ",DC=")
                }
            } catch {
                # Fall back to the simple path if there's an error
                Write-Host "Error finding OU: $($_.Exception.Message), using default path construction" -ForegroundColor Yellow
                $targetPath = "OU=$targetName,DC=" + ($targetDomain -replace "\.", ",DC=")
            }
        }
        Write-Host "Using calculated targetPath (targetDN not available in JSON): $targetPath" -ForegroundColor Yellow
    }
    
    # Create the GPLink
    try {
        Write-Host "Creating GPLink: '$gpoName' to '$targetPath' in domain '$targetDomain'" -ForegroundColor Cyan
        
        # Execute the New-GPLink cmdlet
        New-GPLink -Name $gpoName -Target $targetPath -Domain $targetDomain -ErrorAction Stop
        
        Write-Host "Successfully created GPLink" -ForegroundColor Green
        $successLinks++
    }
    catch {
        Write-Host "Failed to create GPLink: $($_.Exception.Message)" -ForegroundColor Red
        $failedLinks++
    }
}

# Display summary
Write-Host "`n===== GPLink Creation Summary =====" -ForegroundColor Cyan
Write-Host "Total links processed: $totalLinks" -ForegroundColor White
Write-Host "Successfully created: $successLinks" -ForegroundColor Green
Write-Host "Skipped duplicates: $skippedDuplicates" -ForegroundColor Yellow
Write-Host "Failed: $failedLinks" -ForegroundColor Red
Write-Host "=================================" -ForegroundColor Cyan

# Stop the transcript
Stop-Transcript