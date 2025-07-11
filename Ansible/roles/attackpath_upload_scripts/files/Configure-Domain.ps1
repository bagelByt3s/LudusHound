# Main Attack Path Orchestrator Script
# Save as: Configure-Domain.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [switch]$AttackPath,
    
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# Start transcript logging
$LogPath = "C:\windows\tasks\ludushound\AttackPath\Logs"
$LogFile = Join-Path -Path $LogPath -ChildPath "Configure-Domain_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create log directory if it doesn't exist
if (-not (Test-Path -Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    Write-Host "Created log directory: $LogPath" -ForegroundColor Yellow
}

# Start transcript
Start-Transcript -Path $LogFile -Append

Write-Host "Transcript logging started. Log file: $LogFile" -ForegroundColor Green

# Import required modules
Import-Module ActiveDirectory
# Import common functions
. "$PSScriptRoot\Common-Functions.ps1"
# Read the JSON file
try {
    $jsonContent = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
    Write-Host "Successfully loaded JSON file: $FilePath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to read JSON file: $_"
    Stop-Transcript
    exit 1
}
# Extract nodes and edges from JSON
$nodes = $jsonContent.data.nodes
$edges = $jsonContent.data.edges
# Get domain information
$domainInfo = Get-DomainFromNodes -Nodes $nodes
if (-not $domainInfo) {
    Write-Error "Could not determine domain from JSON data"
    Stop-Transcript
    exit 1
}
Write-Host "Using domain: $($domainInfo.Domain)" -ForegroundColor Cyan
Write-Host "Domain DN: $($domainInfo.DN)" -ForegroundColor Cyan
# Process each node based on type
foreach ($nodeId in $nodes.PSObject.Properties.Name) {
    $node = $nodes.$nodeId
    
    switch ($node.kind) {
        "User" {
            & "$PSScriptRoot\Create-Users.ps1" -Node $node -DomainInfo $domainInfo
        }
        "OU" {
            & "$PSScriptRoot\Create-OUs.ps1" -Node $node -DomainInfo $domainInfo
        }
        "Group" {
            & "$PSScriptRoot\Create-Groups.ps1" -Node $node -DomainInfo $domainInfo
        }
        "GPO" {
            & "$PSScriptRoot\Create-GPOs.ps1" -Node $node
        }
        "Computer" {
            Write-Host "Skipping computer object: $($node.label)" -ForegroundColor Cyan
        }
    }
}
# Process relationships (edges)
& "$PSScriptRoot\Create-Relationships.ps1" -Edges $edges -Nodes $nodes -DomainInfo $domainInfo
Write-Host "`nScript execution completed!" -ForegroundColor Green

# Stop transcript logging
Stop-Transcript