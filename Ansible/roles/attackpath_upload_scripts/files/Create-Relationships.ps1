# Create Relationships Orchestrator Script
# Save as: Create-Relationships.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$Edges,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$Nodes,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

# Process all relationships
foreach ($edge in $Edges) {
    $sourceNode = $Nodes.$($edge.source)
    $targetNode = $Nodes.$($edge.target)
    
    switch ($edge.kind) {
        "MemberOf" { 
            & "$PSScriptRoot\Add-MemberOfRelationship.ps1" -SourceNode $sourceNode -TargetNode $targetNode
        }
        "GenericWrite" { 
            & "$PSScriptRoot\Set-GenericWritePermission.ps1" -SourceNode $sourceNode -TargetNode $targetNode -DomainInfo $DomainInfo
        }
        "GenericAll" { 
            & "$PSScriptRoot\Set-GenericAllPermission.ps1" -SourceNode $sourceNode -TargetNode $targetNode -DomainInfo $DomainInfo
        }
        "DCSync" { 
            & "$PSScriptRoot\Set-DCSyncPermission.ps1" -SourceNode $sourceNode -TargetNode $targetNode -DomainInfo $DomainInfo
        }
        "GPLink" { 
            & "$PSScriptRoot\New-GPLink.ps1" -SourceNode $sourceNode -TargetNode $targetNode
        }
        "Contains" { 
            & "$PSScriptRoot\Add-ObjectToOU.ps1" -SourceNode $sourceNode -TargetNode $targetNode
        }
        "ForceChangePassword" { 
            & "$PSScriptRoot\Set-ForceChangePasswordPermission.ps1" -SourceNode $sourceNode -TargetNode $targetNode -DomainInfo $DomainInfo
        }
        "AllowedToDelegate" { 
            & "$PSScriptRoot\Set-ConstrainedDelegationPermission.ps1" -SourceNode $sourceNode -TargetNode $targetNode -DomainInfo $DomainInfo
        }

        default {
            Write-Warning "Unknown relationship type: $($edge.kind)"
        }
    }
}