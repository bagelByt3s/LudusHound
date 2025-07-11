# New GPLink Script
# Save as: New-GPLink.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode
)

function New-GPOLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SourceNode,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$TargetNode
    )
    
    try {
        if ($SourceNode.kind -eq "GPO" -and $TargetNode.kind -eq "OU") {
            $gpoName = $SourceNode.label -replace '@.*$'
            $ouName = $TargetNode.label -replace '@.*$'
            
            $gpo = Get-GPO -Name $gpoName
            $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" | Select-Object -First 1
            
            New-GPLink -Name $gpoName -Target $ou.DistinguishedName
            Write-Host "Linked GPO '$gpoName' to OU '$ouName'" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to link GPO: $_"
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode) {
    New-GPOLink -SourceNode $SourceNode -TargetNode $TargetNode
}