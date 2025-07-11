# Script to add users/groups with CanRDP permissions to the local Remote Desktop Users group
# Save as: Add-RDPUsersFromJson.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$AttackPath
)

function Add-RDPUsersFromJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AttackPath
    )
    
    try {
        # Set up logging
        $logDir = "C:\Windows\Tasks\LudusHound\AttackPath\Logs"
        $logFileName = "RDPPermission_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $logPath = Join-Path -Path $logDir -ChildPath $logFileName
        
        # Ensure log directory exists
        if (-not (Test-Path -Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Host "Created log directory: $logDir" -ForegroundColor Cyan
        }
        
        # Start transcript logging
        Start-Transcript -Path $logPath -Append
        
        Write-Host "Script execution started at $(Get-Date)" -ForegroundColor Cyan
        Write-Host "Attack Path: $AttackPath" -ForegroundColor Cyan
        
        # Get current computer name
        $currentComputer = $env:COMPUTERNAME
        
        Write-Host "Current computer: $currentComputer" -ForegroundColor Cyan
        
        # Read and parse JSON file
        $jsonContent = Get-Content -Path $AttackPath -Raw
        $graphData = $jsonContent | ConvertFrom-Json
        
        # Identify the current computer in the nodes
        $computerNodes = @{}
        foreach ($nodeKey in $graphData.nodes.PSObject.Properties.Name) {
            $node = $graphData.nodes.$nodeKey
            if ($node.kind -eq "Computer") {
                $computerName = $node.label -replace '\..*$' # Remove domain suffix
                $computerNodes[$computerName] = $nodeKey
            }
        }
        
        # If current computer is not in the graph, exit
        if (-not $computerNodes.ContainsKey($currentComputer)) {
            Write-Host "Current computer ($currentComputer) not found in the JSON data." -ForegroundColor Yellow
            Stop-Transcript
            return
        }
        
        Write-Host "Found current computer in JSON data." -ForegroundColor Green
        
        # Get node ID for current computer
        $currentComputerNodeId = $computerNodes[$currentComputer]
        
        # Find all CanRDP edges targeting the current computer
        $rdpEdges = @()
        foreach ($edge in $graphData.edges) {
            if ($edge.kind -eq "CanRDP" -and $edge.target -eq $currentComputerNodeId) {
                $rdpEdges += $edge
            }
        }
        
        if ($rdpEdges.Count -eq 0) {
            Write-Host "No CanRDP relationships found for current computer." -ForegroundColor Yellow
            Stop-Transcript
            return
        }
        
        Write-Host "Found $($rdpEdges.Count) CanRDP relationships for current computer." -ForegroundColor Green
        
        # Process each RDP edge
        foreach ($edge in $rdpEdges) {
            $sourceNodeId = $edge.source
            $sourceNode = $graphData.nodes.$sourceNodeId
            
            if ($sourceNode) {
                $sourceName = $sourceNode.label -replace '@.*$'  # Remove domain suffix
                $sourceKind = $sourceNode.kind
                
                # Add to Remote Desktop Users group
                try {
                    $rdpGroupName = "Remote Desktop Users"
                    $domainName = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
                    
                    # Only process user or group accounts
                    if ($sourceKind -eq "User" -or $sourceKind -eq "Group") {
                        $accountName = "$domainName\$sourceName"
                        
                        Write-Host "Processing $sourceKind '$accountName'..." -ForegroundColor Cyan
                        
                        # Use net localgroup command to add the user or group
                        $netOutput = net localgroup "$rdpGroupName" "$accountName" /add 2>&1
                        
                        # Check output for success or if already a member
                        if ($netOutput -match "successfully") {
                            Write-Host "Added $sourceKind '$accountName' to $rdpGroupName." -ForegroundColor Green
                        } 
                        elseif ($netOutput -match "already a member") {
                            Write-Host "$sourceKind '$accountName' is already a member of $rdpGroupName." -ForegroundColor Yellow
                        }
                        else {
                            Write-Host "Unexpected result when adding $sourceKind '$accountName': $netOutput" -ForegroundColor Red
                            # Try with NETBIOS domain name instead of FQDN
                            $netbiosDomain = $domainName.Split('.')[0]
                            $netbiosAccount = "$netbiosDomain\$sourceName"
                            Write-Host "Trying with NETBIOS domain: $netbiosAccount" -ForegroundColor Cyan
                            
                            $netOutput = net localgroup "$rdpGroupName" "$netbiosAccount" /add 2>&1
                            if ($netOutput -match "successfully") {
                                Write-Host "Added $sourceKind '$netbiosAccount' to $rdpGroupName." -ForegroundColor Green
                            } 
                            elseif ($netOutput -match "already a member") {
                                Write-Host "$sourceKind '$netbiosAccount' is already a member of $rdpGroupName." -ForegroundColor Yellow
                            }
                            else {
                                Write-Host "Failed to add $sourceKind '$sourceName' using both FQDN and NETBIOS formats." -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Host "Skipping '$sourceName' because it's not a User or Group (type: $sourceKind)" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Error "Failed to add '$sourceName' to Remote Desktop Users: $_"
                }
            }
        }
        
        Write-Host "Script execution completed at $(Get-Date)" -ForegroundColor Cyan
        
        # Stop transcript logging
        Stop-Transcript
        
    } catch {
        Write-Error "Error processing JSON file: $_"
        # Ensure transcript is stopped even if an error occurs
        if ((Get-Command Start-Transcript -ErrorAction SilentlyContinue).HelpUri) {
            Stop-Transcript -ErrorAction SilentlyContinue
        }
    }
}

# Execute the function
if (Test-Path -Path $AttackPath) {
    Add-RDPUsersFromJson -AttackPath $AttackPath
} else {
    # Ensure log directory exists for error logging
    $logDir = "C:\Windows\Tasks\LudusHound\AttackPath\Log"
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    # Log the error
    $logFileName = "RDPPermission_Error_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $logPath = Join-Path -Path $logDir -ChildPath $logFileName
    
    Start-Transcript -Path $logPath
    Write-Error "Attack path file not found: $AttackPath"
    Stop-Transcript
}