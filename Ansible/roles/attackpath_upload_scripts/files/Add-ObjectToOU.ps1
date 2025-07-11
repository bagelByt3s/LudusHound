# OU Membership Management Script
# Save as: Add-ObjectToOU.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode
)

function Add-NodeToOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SourceNode,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$TargetNode
    )
    
    try {
        # Check if source node is an OU
        if ($SourceNode.kind -eq "OU") {
            $ouName = $SourceNode.label -replace '@.*$'
            $targetName = $TargetNode.label -replace '@.*$'
            $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" | Select-Object -First 1
            
            if (-not $ou) {
                Write-Warning "OU '$ouName' not found"
                return
            }
            
            switch ($TargetNode.kind) {
                "User" {
                    $targetObject = Get-ADUser -Filter "Name -eq '$targetName'" | Select-Object -First 1
                    if ($targetObject) {
                        Move-ADObject -Identity $targetObject.DistinguishedName -TargetPath $ou.DistinguishedName
                        Write-Host "Added user '$targetName' to OU '$ouName'" -ForegroundColor Green
                    } else {
                        Write-Warning "User '$targetName' not found"
                    }
                }
                "Computer" {
                    #$targetObject = Get-ADComputer -Filter "Name -eq '$targetName'" | Select-Object -First 1
                    if (($targetName.ToCharArray() | Where-Object {$_ -eq '.'}).Count -ge 2) {
                        $targetObject = Get-ADComputer -Filter "DnsHostName -eq '$targetName'" | Select-Object -First 1
                    } else {
                        $targetObject = Get-ADComputer -Filter "Name -eq '$targetName'" | Select-Object -First 1
                    }
                    
                    if ($targetObject) {
                        Move-ADObject -Identity $targetObject.DistinguishedName -TargetPath $ou.DistinguishedName
                        Write-Host "Added computer '$targetName' to OU '$ouName'" -ForegroundColor Green
                    } else {
                        Write-Warning "Computer '$targetName' not found"
                    }
                }
                "Group" {
                    $targetObject = Get-ADGroup -Filter "Name -eq '$targetName'" | Select-Object -First 1
                    if ($targetObject) {
                        Move-ADObject -Identity $targetObject.DistinguishedName -TargetPath $ou.DistinguishedName
                        Write-Host "Added group '$targetName' to OU '$ouName'" -ForegroundColor Green
                    } else {
                        Write-Warning "Group '$targetName' not found"
                    }
                }
                "OU" {
                    $targetObject = Get-ADOrganizationalUnit -Filter "Name -eq '$targetName'" | Select-Object -First 1
                    if ($targetObject) {
                        Move-ADObject -Identity $targetObject.DistinguishedName -TargetPath $ou.DistinguishedName
                        Write-Host "Added child OU '$targetName' to parent OU '$ouName'" -ForegroundColor Green
                    } else {
                        Write-Warning "OU '$targetName' not found"
                    }
                }
                default {
                    Write-Warning "Unsupported target type: $($TargetNode.kind)"
                }
            }
        }
        else {
            Write-Warning "Source node must be an OU. Current source kind: $($SourceNode.kind)"
        }
    }
    catch {
        Write-Error "Failed to add node to OU: $_"
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode) {
    Add-NodeToOU -SourceNode $SourceNode -TargetNode $TargetNode
}