# Create Groups Script
# Save as: Create-Groups.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$Node,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function New-ADGroupFromNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Node,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DomainInfo
    )
    
    try {
        $groupName = $Node.label -replace '@.*$'
        
        $existingGroup = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
        
        if (-not $existingGroup) {
            $groupParams = @{
                Name = $groupName
                SamAccountName = $groupName
                GroupScope = "Global"
                GroupCategory = "Security"
                Path = "CN=Users,$($DomainInfo.DN)"
                Description = "Created by Attack Path script"
            }
            
            New-ADGroup @groupParams
            Write-Host "Created group: $groupName" -ForegroundColor Green
        }
        else {
            Write-Host "Group already exists: $groupName" -ForegroundColor Yellow
        }
        
        return Get-ADGroup -Identity $groupName
    }
    catch {
        Write-Error "Failed to create group '$($Node.label)': $_"
        return $null
    }
}

# Execute if running directly
if ($Node -and $DomainInfo) {
    New-ADGroupFromNode -Node $Node -DomainInfo $DomainInfo
}