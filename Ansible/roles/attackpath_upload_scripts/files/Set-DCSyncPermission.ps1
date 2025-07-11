# Set DCSync Permission Script
# Save as: Set-DCSyncPermission.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function Set-DCSyncPermission {
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
        # Extract source name without domain suffix
        $sourceName = $SourceNode.label -replace '@.*$'
        
        # Verify target is Domain type
        if ($TargetNode.kind -ne "Domain") {
            Write-Warning "DCSync permissions can only be set on Domain objects, but target is $($TargetNode.kind)"
            return
        }
        
        # Extract target domain information
        $domainName = $TargetNode.label
        $domainDN = $DomainInfo.DN
        
        Write-Host "Setting DCSync permission from '$sourceName' to domain '$domainName'" -ForegroundColor Cyan
        
        # Handle different types of source objects
        switch ($SourceNode.kind) {
            "User" {
                # Find the user object
                $userObject = Get-ADUser -Identity $sourceName
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($userObject.SID)
                
                # Get the ACL of the domain object
                $acl = Get-Acl -Path "AD:$domainDN"
                
                # Create new access rules for the specific extended rights needed for DCSync
                $guidMap = @{
                    # Right to Replicating Directory Changes
                    "DS-Replication-Get-Changes" = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                    # Right to Replicating Directory Changes All
                    "DS-Replication-Get-Changes-All" = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
                    # Right to Replicating Directory Changes In Filtered Set
                    "DS-Replication-Get-Changes-In-Filtered-Set" = [GUID]"89e95b76-444d-4c62-991a-0facbeda640c"
                }
                
                foreach ($right in $guidMap.Keys) {
                    $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                    $type = [System.Security.AccessControl.AccessControlType]::Allow
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sourceIdentity, 
                        $adRights, 
                        $type, 
                        $guidMap[$right]
                    )
                    
                    # Add the rule to the ACL
                    $acl.AddAccessRule($ace)
                }
                
                # Apply the modified ACL to the domain object
                Set-Acl -Path "AD:$domainDN" -AclObject $acl
                
                Write-Host "Granted DCSync permission to user '$sourceName' on domain '$domainName'" -ForegroundColor Green
            }
            "Computer" {
                # Try to find the computer object using filter
                try {
                    # Extract computer name
                    if ($sourceName -match '^([^\.@]+)') {
                        $computerName = $matches[1]
                    } else {
                        $computerName = $sourceName
                    }
                    
                    # Get computer object
                    $computerObject = Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction Stop
                    
                    if (-not $computerObject) {
                        # Try broader search
                        Write-Host "Trying broader search for computer '$computerName'..." -ForegroundColor Yellow
                        $computerObject = Get-ADComputer -Filter "Name -like '$computerName*'" -ErrorAction Stop | Select-Object -First 1
                    }
                    
                    if ($computerObject) {
                        $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($computerObject.SID)
                        
                        # Get the ACL of the domain object
                        $acl = Get-Acl -Path "AD:$domainDN"
                        
                        # Create new access rules for the specific extended rights needed for DCSync
                        $guidMap = @{
                            # Right to Replicating Directory Changes
                            "DS-Replication-Get-Changes" = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                            # Right to Replicating Directory Changes All
                            "DS-Replication-Get-Changes-All" = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
                            # Right to Replicating Directory Changes In Filtered Set
                            "DS-Replication-Get-Changes-In-Filtered-Set" = [GUID]"89e95b76-444d-4c62-991a-0facbeda640c"
                        }
                        
                        foreach ($right in $guidMap.Keys) {
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                                $sourceIdentity, 
                                $adRights, 
                                $type, 
                                $guidMap[$right]
                            )
                            
                            # Add the rule to the ACL
                            $acl.AddAccessRule($ace)
                        }
                        
                        # Apply the modified ACL to the domain object
                        Set-Acl -Path "AD:$domainDN" -AclObject $acl
                        
                        Write-Host "Granted DCSync permission to computer '$($computerObject.Name)' on domain '$domainName'" -ForegroundColor Green
                    } else {
                        Write-Error "Computer object '$computerName' not found in Active Directory"
                    }
                }
                catch {
                    Write-Error "Failed to find or access computer object: $_"
                }
            }
            "Group" {
                # Find the group object
                $groupObject = Get-ADGroup -Identity $sourceName
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($groupObject.SID)
                
                # Get the ACL of the domain object
                $acl = Get-Acl -Path "AD:$domainDN"
                
                # Create new access rules for the specific extended rights needed for DCSync
                $guidMap = @{
                    # Right to Replicating Directory Changes
                    "DS-Replication-Get-Changes" = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                    # Right to Replicating Directory Changes All
                    "DS-Replication-Get-Changes-All" = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
                    # Right to Replicating Directory Changes In Filtered Set
                    "DS-Replication-Get-Changes-In-Filtered-Set" = [GUID]"89e95b76-444d-4c62-991a-0facbeda640c"
                }
                
                foreach ($right in $guidMap.Keys) {
                    $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                    $type = [System.Security.AccessControl.AccessControlType]::Allow
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sourceIdentity, 
                        $adRights, 
                        $type, 
                        $guidMap[$right]
                    )
                    
                    # Add the rule to the ACL
                    $acl.AddAccessRule($ace)
                }
                
                # Apply the modified ACL to the domain object
                Set-Acl -Path "AD:$domainDN" -AclObject $acl
                
                Write-Host "Granted DCSync permission to group '$sourceName' on domain '$domainName'" -ForegroundColor Green
            }
            default {
                Write-Warning "Unsupported source kind: $($SourceNode.kind) for DCSync permission"
            }
        }
    }
    catch {
        Write-Error "Failed to set DCSync permission: $_"
        Write-Host "Source: $($SourceNode.label) ($($SourceNode.kind))" -ForegroundColor Yellow
        Write-Host "Target: $($TargetNode.label) ($($TargetNode.kind))" -ForegroundColor Yellow
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode -and $DomainInfo) {
    Set-DCSyncPermission -SourceNode $SourceNode -TargetNode $TargetNode -DomainInfo $DomainInfo
}