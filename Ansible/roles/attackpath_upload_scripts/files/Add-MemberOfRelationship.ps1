# Add MemberOf Relationship Script
# Save as: Add-MemberOfRelationship.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode
)

function Add-MemberOfRelationship {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SourceNode,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$TargetNode
    )
    
    try {
        if ($SourceNode.kind -eq "User" -and $TargetNode.kind -eq "Group") {
            $samAccountName = $SourceNode.label -replace '@.*$'
            $groupName = $TargetNode.label -replace '@.*$'
            
            Add-ADGroupMember -Identity $groupName -Members $samAccountName
            Write-Host "Added user '$samAccountName' to group '$groupName'" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to add membership: $_"
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode) {
    Add-MemberOfRelationship -SourceNode $SourceNode -TargetNode $TargetNode
}