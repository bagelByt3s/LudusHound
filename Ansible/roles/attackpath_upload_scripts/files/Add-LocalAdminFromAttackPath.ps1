<#
.SYNOPSIS
    Adds admin users/groups from an attack path JSON to the local administrators group.

.PARAMETER AttackPath
    The path to the JSON file containing the attack path data.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$AttackPath
)

# Create log directory
$logDir = "C:\Windows\Tasks\LudusHound\AttackPath\Logs"
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Start transcript logging
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path -Path $logDir -ChildPath "AddLocalAdminFromAttackPath_$timestamp.log"
Start-Transcript -Path $logFile -Force

# Get current computer name
$currentComputer = $env:COMPUTERNAME
Write-Host "Current computer: $currentComputer"

# Read and parse the JSON file
try {
    $jsonContent = Get-Content -Path $AttackPath -Raw | ConvertFrom-Json
    
    # Extract nodes and edges
    $nodes = $jsonContent.data.nodes
    $edges = $jsonContent.data.edges
    
    Write-Host "Found $($nodes.PSObject.Properties.Count) nodes and $($edges.Count) edges"
    
    # Process AdminTo edges
    foreach ($edge in $edges) {
        if ($edge.kind -eq "AdminTo") {
            $sourceId = $edge.source
            $targetId = $edge.target
            
            $sourceNode = $nodes.$sourceId
            $targetNode = $nodes.$targetId
            
            if ($sourceNode -and $targetNode) {
                Write-Host "Processing AdminTo edge: $($sourceNode.label) -> $($targetNode.label)"
                
                # Check if target is current computer
                if ($targetNode.kind -eq "Computer" -and $targetNode.label -match $currentComputer) {
                    Write-Host "Target matches current computer"
                    
                    if ($sourceNode.kind -eq "User" -or $sourceNode.kind -eq "Group") {
                        $parts = $sourceNode.label -split '@'
                        if ($parts.Count -eq 2) {
                            $name = $parts[0]
                            $domain = $parts[1].Split('.')[0]
                            $account = "$domain\$name"
                            
                            Write-Host "Adding $account to Administrators group"
                            
                            # Execute the net localgroup command with the correct format
                            $cmd = "net localgroup administrators $account /add"
                            Write-Host "Executing: $cmd"
                            
                            cmd.exe /c $cmd
                            
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "Successfully added $account to Administrators group"
                            }
                            else {
                                Write-Host "Failed to add $account. Exit code: $LASTEXITCODE"
                            }
                        }
                        else {
                            Write-Host "Could not parse account from $($sourceNode.label)"
                        }
                    }
                    else {
                        Write-Host "Source node is not a user or group"
                    }
                }
                else {
                    Write-Host "Target does not match current computer"
                }
            }
        }
    }
}
catch {
    Write-Host "Error processing attack path: $_"
}
finally {
    Stop-Transcript
}