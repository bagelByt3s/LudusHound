# Create Users Script
# Save as: Create-Users.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$Node,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function New-ADUserFromNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Node,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DomainInfo
    )
    
    try {
        $samAccountName = $Node.label -replace '@.*$'
        $displayName = $samAccountName
        
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue
        
        if (-not $existingUser) {
            $userParams = @{
                Name = $displayName
                SamAccountName = $samAccountName
                UserPrincipalName = $Node.label
                DisplayName = $displayName
                Enabled = $true
                AccountPassword = (ConvertTo-SecureString "password" -AsPlainText -Force)
                ChangePasswordAtLogon = $false
                Path = "CN=Users,$($DomainInfo.DN)"
            }
            
            New-ADUser @userParams
            Write-Host "Created user: $($Node.label)" -ForegroundColor Green
        }
        else {
            Write-Host "User already exists: $($Node.label)" -ForegroundColor Yellow
        }
        
        return Get-ADUser -Identity $samAccountName
    }
    catch {
        Write-Error "Failed to create user '$($Node.label)': $_"
        return $null
    }
}

# Execute if running directly
if ($Node -and $DomainInfo) {
    New-ADUserFromNode -Node $Node -DomainInfo $DomainInfo
}