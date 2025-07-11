# DNS Conditional Forwarder Configuration Script
param (
    [Parameter(Mandatory=$true)]
    [string]$f,
    
    [Parameter(Mandatory=$false)]
    [switch]$NotChildDomains,
    
    [Parameter(Mandatory=$false)]
    [switch]$ChildDomains
)

# Define a default domain name for logging
$scriptName = "Configure_DNS"

# Define the log directory path - using a fixed path
$logDirectory = ".\Log\DNS"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    try {
        New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "Created log directory: $logDirectory" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create log directory: $_"
        # Continue execution even if log directory creation fails
    }
}

# Define the log file path with a timestamp
$logPath = Join-Path -Path $logDirectory -ChildPath "$scriptName`_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
try {
    Start-Transcript -Path $logPath -ErrorAction Stop
} catch {
    Write-Warning "Could not start transcript: $_"
    # Continue execution even if transcript fails
}

# Log the start of the script
Write-Host "DNS Config script started at $(Get-Date)" -ForegroundColor Cyan

# Get the current domain
try {
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-Host "Current domain is: $currentDomain" -ForegroundColor Cyan
    
    # Convert to uppercase to match JSON format
    $currentDomainUpper = $currentDomain.ToUpper()
    Write-Host "Will skip DNS forwarding setup for domain: $currentDomainUpper" -ForegroundColor Yellow
} catch {
    Write-Warning "Could not determine current domain: $_"
    $currentDomainUpper = $null
}

# Verify the file exists
if (-not (Test-Path $f)) {
    Write-Error "File not found: $f"
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

# Read and parse the JSON file
try {
    $jsonContent = Get-Content -Path $f -Raw -ErrorAction Stop
    $systemsData = $jsonContent | ConvertFrom-Json -ErrorAction Stop
    
    # Verify the JSON has the expected structure
    if (-not (Get-Member -InputObject $systemsData -Name "systems" -MemberType Properties)) {
        throw "JSON file does not contain a 'systems' property"
    }
} catch {
    Write-Error "Failed to parse JSON file: $_"
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

# Check if both flags are specified
if ($NotChildDomains -and $ChildDomains) {
    Write-Warning "Both -NotChildDomains and -ChildDomains flags specified. Using all domains."
    $NotChildDomains = $false
    $ChildDomains = $false
}

# Create a hashtable to store domain to IP mappings
$domainMappings = @{}

# Log domain selection mode
if ($NotChildDomains) {
    Write-Host "Running in -NotChildDomains mode. Only processing non-child domains." -ForegroundColor Yellow
} elseif ($ChildDomains) {
    Write-Host "Running in -ChildDomains mode. Only processing child domains." -ForegroundColor Yellow
} else {
    Write-Host "Processing all domains." -ForegroundColor Yellow
}

# Process each system in the JSON
$systemCount = 0
$dcCount = 0
foreach ($system in $systemsData.systems) {
    $systemCount++
    
    # Since the JSON doesn't have an isChildDomainVariable property, we'll determine it based on domain structure
    # Assume a domain with more than 2 parts (e.g., citadel.covertius.local) is a child domain
    $domain = $system.domain.ToUpper() # Convert to uppercase for consistency
    $isChildDomain = $domain.Split(".").Count -gt 2
    
    # Skip if domain matches current domain
    if ($domain -eq $currentDomainUpper) {
        Write-Host "Skipping current domain: $domain" -ForegroundColor Yellow
        continue
    }
    
    # Check if this system is a Domain Controller
    if (-not ($system.PSObject.Properties.Name -contains "ComputerRole") -or $system.ComputerRole -ne "DC") {
        Write-Host "Skipping non-DC system: $($system.hostname) with role $($system.ComputerRole)" -ForegroundColor Gray
        continue
    }
    
    $dcCount++
    
    if ($NotChildDomains -and $isChildDomain) {
        Write-Host "Skipping child domain DC: $($system.hostname) with domain $domain" -ForegroundColor Gray
        continue
    }
    
    if ($ChildDomains -and -not $isChildDomain) {
        Write-Host "Skipping non-child domain DC: $($system.hostname) with domain $domain" -ForegroundColor Gray
        continue
    }
    
    # Ensure required properties exist
    if (-not ($system.PSObject.Properties.Name -contains "hostname" -and 
              $system.PSObject.Properties.Name -contains "domain" -and 
              $system.PSObject.Properties.Name -contains "ipAddr")) {
        Write-Warning "System is missing required properties (hostname, domain, or ipAddr). Skipping."
        continue
    }
    
    $hostname = $system.hostname
    $ipAddr = $system.ipAddr
    
    Write-Host "Processing DC system: $hostname with domain $domain and IP $ipAddr"
    
    # Add the domain and IP to the hashtable if not already present
    if (-not $domainMappings.ContainsKey($domain)) {
        $domainMappings[$domain] = $ipAddr
        Write-Host "Added mapping: $domain -> $ipAddr"
    }
}

# Check if any systems were processed
if ($systemCount -eq 0) {
    Write-Warning "No systems found in the JSON file. Nothing to process."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

if ($dcCount -eq 0) {
    Write-Warning "No Domain Controllers found in the JSON file. Nothing to process."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

if ($domainMappings.Count -eq 0) {
    Write-Warning "No domains matched the filter criteria. Nothing to configure."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 0
}

# Configure DNS conditional forwarders
$successCount = 0
$failCount = 0
foreach ($domain in $domainMappings.Keys) {
    $ipAddr = $domainMappings[$domain]
    
    Write-Host "Configuring conditional forwarder for domain: $domain with IP: $ipAddr" -ForegroundColor Cyan
    
    try {
        # Check if conditional forwarder already exists
        $existingZone = Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue
        
        if ($existingZone) {
            # Update existing forwarder
            Set-DnsServerConditionalForwarderZone -Name $domain -MasterServers $ipAddr -ErrorAction Stop
            Write-Host "Updated existing conditional forwarder for $domain" -ForegroundColor Green
        } else {
            # Add new forwarder
            Add-DnsServerConditionalForwarderZone -Name $domain -MasterServers $ipAddr -ErrorAction Stop
            Write-Host "Successfully added conditional forwarder for $domain" -ForegroundColor Green
        }
        $successCount++
    } catch {
        Write-Warning "Failed to configure conditional forwarder for $domain. Error: $_"
        $failCount++
    }
}

# Summary
Write-Host "DNS conditional forwarder configuration completed." -ForegroundColor Cyan
Write-Host "Total systems processed: $systemCount" -ForegroundColor Cyan
Write-Host "Domain Controllers found: $dcCount" -ForegroundColor Cyan
Write-Host "Successfully configured: $successCount domains" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "Failed to configure: $failCount domains" -ForegroundColor Red
}

# End the logging
try {
    Stop-Transcript -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not stop transcript: $_"
}

# Log the end of the script
Write-Host "DNS script ended at $(Get-Date)" -ForegroundColor Cyan