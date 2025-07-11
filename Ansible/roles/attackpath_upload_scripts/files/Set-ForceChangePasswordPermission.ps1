# Set ForceChangePassword Permission Script
# Save as: Set-ForceChangePasswordPermission.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function Set-ForceChangePasswordPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$SourceNode,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$TargetNode,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DomainInfo
    )
    
    try {
        if ($SourceNode.kind -eq "User" -and $TargetNode.kind -eq "User") {
            $sourceUser = $SourceNode.label -replace '@.*$'
            $targetUser = $TargetNode.label -replace '@.*$'
            
            # Get source and target user objects
            $sourceADUser = Get-ADUser -Identity $sourceUser
            $targetADUser = Get-ADUser -Identity $targetUser
            
            # Set ACL to grant Force Change Password permission
            $targetDN = $targetADUser.DistinguishedName
            $acl = Get-Acl -Path "AD:\$targetDN"
            
            # Create ACE for Force Change Password
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sourceADUser.SID)
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $guid = New-Object Guid "00299570-246d-11d0-a768-00aa006e0529" # Right to change password
            
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $identity,
                $adRights,
                $type,
                $guid
            )
            $acl.AddAccessRule($ace)
            
            Set-Acl -Path "AD:\$targetDN" -AclObject $acl
            Write-Host "Granted Force Change Password permission to '$sourceUser' on user '$targetUser'" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to set Force Change Password permission: $_"
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode -and $DomainInfo) {
    Set-ForceChangePasswordPermission -SourceNode $SourceNode -TargetNode $TargetNode -DomainInfo $DomainInfo
}