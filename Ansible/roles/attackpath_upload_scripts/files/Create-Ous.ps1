# Create OUs Script
# Save as: Create-OUs.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$Node,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function New-ADOUFromNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Node,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DomainInfo
    )
    
    try {
        # Extract OU name without domain suffix
        $ouName = $Node.label -replace '@.*$'
        
        # Check if parent path is specified in the Node
        $parentPath = $null
        if ($Node.PSObject.Properties.Name -contains "parentPath") {
            $parentPath = $Node.parentPath
        }
        
        # Default path is domain root if no parent path specified
        $ouPath = if ($parentPath) { $parentPath } else { $DomainInfo.DN }
        
        # Check if OU already exists
        $existingOU = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue
        
        if (-not $existingOU) {
            # Prepare parameters for New-ADOrganizationalUnit
            $ouParams = @{
                Name = $ouName
                Path = $ouPath
                Description = "OU created for $ouName"
                ProtectedFromAccidentalDeletion = $true
            }
            
            # Create the OU
            New-ADOrganizationalUnit @ouParams
            Write-Host "Created OU: $ouName in $ouPath" -ForegroundColor Green
        }
        else {
            Write-Host "OU already exists: $ouName" -ForegroundColor Yellow
        }
        
        # Return the OU object
        return Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "Failed to create OU '$($Node.label)': $_"
        return $null
    }
}

# Execute if running directly
if ($Node -and $DomainInfo) {
    New-ADOUFromNode -Node $Node -DomainInfo $DomainInfo
}