# Set GenericAll Permission Script
# Save as: Set-GenericAllPermission.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function Set-GenericAllPermission {
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
        
        # Extract target information
        $targetName = $TargetNode.label
        $targetType = $TargetNode.kind
        
        # Process based on target type
        if ($targetType -eq "Computer") {
            # For computer objects, try to get the name without domain
            # Try multiple formats: FQDN, NetBIOS, or with @ symbol
            if ($targetName -match '^([^\.@]+)') {
                $computerName = $matches[1]
            } else {
                $computerName = $targetName
            }
            
            Write-Host "Setting GenericAll permission from '$sourceName' to computer '$computerName'" -ForegroundColor Cyan
        } else {
            # For other object types, remove domain suffix
            $targetName = $targetName -replace '@.*$'
            Write-Host "Setting GenericAll permission from '$sourceName' to '$targetName'" -ForegroundColor Cyan
        }
        
        # Handle different types of source and target objects
        switch ($SourceNode.kind) {
            "Group" {
                $sourceObject = Get-ADGroup -Identity $sourceName
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($sourceObject.SID)
                
                switch ($TargetNode.kind) {
                    "User" {
                        $targetObject = Get-ADUser -Identity $targetName
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl
                        
                        Write-Host "Granted GenericAll permission to group '$sourceName' on user '$targetName'" -ForegroundColor Green
                    }
                    "Computer" {
                        # Try to find the computer object directly by filter
                        try {
                            # Use a -Filter approach instead of -Identity
                            $computerObject = Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction Stop
                            
                            if (-not $computerObject) {
                                # If still not found, try a broader search
                                Write-Host "Trying broader search for computer '$computerName'..." -ForegroundColor Yellow
                                $computerObject = Get-ADComputer -Filter "Name -like '$computerName*'" -ErrorAction Stop | Select-Object -First 1
                            }
                            
                            if ($computerObject) {
                                $targetDN = $computerObject.DistinguishedName
                                
                                # Get the ACL of the target object
                                $acl = Get-Acl -Path "AD:$targetDN"
                                
                                # Create a new access rule
                                $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                                $type = [System.Security.AccessControl.AccessControlType]::Allow
                                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                                
                                # Add the rule and set the ACL
                                $acl.AddAccessRule($ace)
                                Set-Acl -Path "AD:$targetDN" -AclObject $acl
                                
                                Write-Host "Granted GenericAll permission to group '$sourceName' on computer '$($computerObject.Name)'" -ForegroundColor Green
                            } else {
                                Write-Error "Computer object '$computerName' not found in Active Directory"
                            }
                        }
                        catch {
                            Write-Error "Failed to find or access computer object: $_"
                        }
                    }
                    "Group" {
                        $targetObject = Get-ADGroup -Identity $targetName
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl
                        
                        Write-Host "Granted GenericAll permission to group '$sourceName' on group '$targetName'" -ForegroundColor Green
                    }
                    "OU" {
                        # Find the OU object
                        try {
                            $ouObject = Get-ADOrganizationalUnit -Filter "Name -eq '$targetName'" -ErrorAction Stop
                            
                            if (-not $ouObject) {
                                Write-Error "OU '$targetName' not found in Active Directory"
                                return
                            }
                            
                            $targetDN = $ouObject.DistinguishedName
                            
                            # Get the ACL of the target object
                            $acl = Get-Acl -Path "AD:$targetDN"
                            
                            # Create a new access rule
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                            
                            # Add the rule and set the ACL
                            $acl.AddAccessRule($ace)
                            Set-Acl -Path "AD:$targetDN" -AclObject $acl
                            
                            Write-Host "Granted GenericAll permission to group '$sourceName' on OU '$targetName'" -ForegroundColor Green
                        }
                        catch {
                            Write-Error "Failed to find or access OU object: $_"
                        }
                    }
                    "Domain" {
                        # Get the domain object
                        $domainDN = $DomainInfo.DN
                        
                        # Get the ACL of the domain object
                        $acl = Get-Acl -Path "AD:$domainDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$domainDN" -AclObject $acl
                        
                        Write-Host "Granted GenericAll permission to group '$sourceName' on domain '$targetName'" -ForegroundColor Green
                    }                    
                    "GPO" {
                        #$targetObject = Get-ADUser -Identity $targetName
                        $targetObject = Get-ADObject -Filter "DisplayName -eq '$targetName'" -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties name,displayname
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl    
                        
                        Write-Host "Granted GenericAll permission to group '$sourceName' to GPO '$targetName'" -ForegroundColor Green
                    }
                    default {
                        Write-Warning "Unsupported target kind: $($TargetNode.kind) for source kind: $($SourceNode.kind)"
                    }
                }
            }
            "User" {
                $sourceObject = Get-ADUser -Identity $sourceName
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($sourceObject.SID)
                
                switch ($TargetNode.kind) {
                    "User" {
                        $targetObject = Get-ADUser -Identity $targetName
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl
                        
                        Write-Host "Granted GenericAll permission to user '$sourceName' on user '$targetName'" -ForegroundColor Green
                    }
                    "Computer" {
                        try {
                            # Use a -Filter approach instead of -Identity
                            $computerObject = Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction Stop
                            
                            if (-not $computerObject) {
                                # If still not found, try a broader search
                                Write-Host "Trying broader search for computer '$computerName'..." -ForegroundColor Yellow
                                $computerObject = Get-ADComputer -Filter "Name -like '$computerName*'" -ErrorAction Stop | Select-Object -First 1
                            }
                            
                            if ($computerObject) {
                                $targetDN = $computerObject.DistinguishedName
                                
                                # Get the ACL of the target object
                                $acl = Get-Acl -Path "AD:$targetDN"
                                
                                # Create a new access rule
                                $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                                $type = [System.Security.AccessControl.AccessControlType]::Allow
                                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                                
                                # Add the rule and set the ACL
                                $acl.AddAccessRule($ace)
                                Set-Acl -Path "AD:$targetDN" -AclObject $acl
                                
                                Write-Host "Granted GenericAll permission to user '$sourceName' on computer '$($computerObject.Name)'" -ForegroundColor Green
                            } else {
                                Write-Error "Computer object '$computerName' not found in Active Directory"
                            }
                        }
                        catch {
                            Write-Error "Failed to find or access computer object: $_"
                        }
                    }
                    "Group" {
                        $targetObject = Get-ADGroup -Identity $targetName
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl
                        
                        Write-Host "Granted GenericAll permission to user '$sourceName' on group '$targetName'" -ForegroundColor Green
                    }
                    "OU" {
                        # Find the OU object
                        try {
                            $ouObject = Get-ADOrganizationalUnit -Filter "Name -eq '$targetName'" -ErrorAction Stop
                            
                            if (-not $ouObject) {
                                Write-Error "OU '$targetName' not found in Active Directory"
                                return
                            }
                            
                            $targetDN = $ouObject.DistinguishedName
                            
                            # Get the ACL of the target object
                            $acl = Get-Acl -Path "AD:$targetDN"
                            
                            # Create a new access rule
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                            
                            # Add the rule and set the ACL
                            $acl.AddAccessRule($ace)
                            Set-Acl -Path "AD:$targetDN" -AclObject $acl
                            
                            Write-Host "Granted GenericAll permission to user '$sourceName' on OU '$targetName'" -ForegroundColor Green
                        }
                        catch {
                            Write-Error "Failed to find or access OU object: $_"
                        }
                    }
                    "Domain" {
                        # Get the domain object
                        $domainDN = $DomainInfo.DN
                        
                        # Get the ACL of the domain object
                        $acl = Get-Acl -Path "AD:$domainDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$domainDN" -AclObject $acl
                        
                        Write-Host "Granted GenericAll permission to user '$sourceName' on domain '$targetName'" -ForegroundColor Green
                    }
                    "GPO" {
                        #$targetObject = Get-ADUser -Identity $targetName
                        $targetObject = Get-ADObject -Filter "DisplayName -eq '$targetName'" -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties name,displayname
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl    
                        
                        Write-Host "Granted GenericAll permission to group '$sourceName' to GPO '$targetName'" -ForegroundColor Green
                    }
                    default {
                        Write-Warning "Unsupported target kind: $($TargetNode.kind) for source kind: $($SourceNode.kind)"
                    }
                }
            }
            "Computer" {
                # Handle computer source objects
                try {
                    # Extract computer name
                    if ($sourceName -match '^([^\.@]+)') {
                        $sourceComputerName = $matches[1]
                    } else {
                        $sourceComputerName = $sourceName
                    }
                    
                    # Find the computer object
                    $sourceObject = Get-ADComputer -Filter "Name -eq '$sourceComputerName'" -ErrorAction Stop
                    
                    if (-not $sourceObject) {
                        # Try broader search
                        $sourceObject = Get-ADComputer -Filter "Name -like '$sourceComputerName*'" -ErrorAction Stop | Select-Object -First 1
                    }
                    
                    if (-not $sourceObject) {
                        Write-Error "Computer object '$sourceComputerName' not found in Active Directory"
                        return
                    }
                    
                    $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($sourceObject.SID)
                    
                    switch ($TargetNode.kind) {
                        "User" {
                            $targetObject = Get-ADUser -Identity $targetName
                            $targetDN = $targetObject.DistinguishedName
                            
                            # Get the ACL of the target object
                            $acl = Get-Acl -Path "AD:$targetDN"
                            
                            # Create a new access rule
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                            
                            # Add the rule and set the ACL
                            $acl.AddAccessRule($ace)
                            Set-Acl -Path "AD:$targetDN" -AclObject $acl
                            
                            Write-Host "Granted GenericAll permission to computer '$($sourceObject.Name)' on user '$targetName'" -ForegroundColor Green
                        }
                        "Computer" {
                            # Try to find the target computer object
                            $targetObject = Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction Stop
                            
                            if (-not $targetObject) {
                                # Try broader search
                                $targetObject = Get-ADComputer -Filter "Name -like '$computerName*'" -ErrorAction Stop | Select-Object -First 1
                            }
                            
                            if ($targetObject) {
                                $targetDN = $targetObject.DistinguishedName
                                
                                # Get the ACL of the target object
                                $acl = Get-Acl -Path "AD:$targetDN"
                                
                                # Create a new access rule
                                $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                                $type = [System.Security.AccessControl.AccessControlType]::Allow
                                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                                
                                # Add the rule and set the ACL
                                $acl.AddAccessRule($ace)
                                Set-Acl -Path "AD:$targetDN" -AclObject $acl
                                
                                Write-Host "Granted GenericAll permission to computer '$($sourceObject.Name)' on computer '$($targetObject.Name)'" -ForegroundColor Green
                            } else {
                                Write-Error "Computer object '$computerName' not found in Active Directory"
                            }
                        }
                        "Group" {
                            $targetObject = Get-ADGroup -Identity $targetName
                            $targetDN = $targetObject.DistinguishedName
                            
                            # Get the ACL of the target object
                            $acl = Get-Acl -Path "AD:$targetDN"
                            
                            # Create a new access rule
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                            
                            # Add the rule and set the ACL
                            $acl.AddAccessRule($ace)
                            Set-Acl -Path "AD:$targetDN" -AclObject $acl
                            
                            Write-Host "Granted GenericAll permission to computer '$($sourceObject.Name)' on group '$targetName'" -ForegroundColor Green
                        }
                        "OU" {
                            # Find the OU object
                            $ouObject = Get-ADOrganizationalUnit -Filter "Name -eq '$targetName'" -ErrorAction Stop
                            
                            if (-not $ouObject) {
                                Write-Error "OU '$targetName' not found in Active Directory"
                                return
                            }
                            
                            $targetDN = $ouObject.DistinguishedName
                            
                            # Get the ACL of the target object
                            $acl = Get-Acl -Path "AD:$targetDN"
                            
                            # Create a new access rule
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                            
                            # Add the rule and set the ACL
                            $acl.AddAccessRule($ace)
                            Set-Acl -Path "AD:$targetDN" -AclObject $acl
                            
                            Write-Host "Granted GenericAll permission to computer '$($sourceObject.Name)' on OU '$targetName'" -ForegroundColor Green
                        }
                        "Domain" {
                            # Get the domain object
                            $domainDN = $DomainInfo.DN
                            
                            # Get the ACL of the domain object
                            $acl = Get-Acl -Path "AD:$domainDN"
                            
                            # Create a new access rule
                            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                            $type = [System.Security.AccessControl.AccessControlType]::Allow
                            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                            
                            # Add the rule and set the ACL
                            $acl.AddAccessRule($ace)
                            Set-Acl -Path "AD:$domainDN" -AclObject $acl
                            
                            Write-Host "Granted GenericAll permission to computer '$($sourceObject.Name)' on domain '$targetName'" -ForegroundColor Green
                        }
                        "GPO" {
                        #$targetObject = Get-ADUser -Identity $targetName
                        $targetObject = Get-ADObject -Filter "DisplayName -eq '$targetName'" -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties name,displayname
                        $targetDN = $targetObject.DistinguishedName
                        
                        # Get the ACL of the target object
                        $acl = Get-Acl -Path "AD:$targetDN"
                        
                        # Create a new access rule
                        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                        $type = [System.Security.AccessControl.AccessControlType]::Allow
                        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
                        
                        # Add the rule and set the ACL
                        $acl.AddAccessRule($ace)
                        Set-Acl -Path "AD:$targetDN" -AclObject $acl    
                        
                        Write-Host "Granted GenericAll permission to group '$sourceName' to GPO '$targetName'" -ForegroundColor Green
                    }
                        default {
                            Write-Warning "Unsupported target kind: $($TargetNode.kind) for source kind: $($SourceNode.kind)"
                        }
                    }
                }
                catch {
                    Write-Error "Failed to process computer source: $_"
                }
            }
            default {
                Write-Warning "Unsupported source kind: $($SourceNode.kind)"
            }
        }
    }
    catch {
        Write-Error "Failed to set GenericAll permission: $_"
        Write-Host "Source: $($SourceNode.label) ($($SourceNode.kind))" -ForegroundColor Yellow
        Write-Host "Target: $($TargetNode.label) ($($TargetNode.kind))" -ForegroundColor Yellow
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode -and $DomainInfo) {
    Set-GenericAllPermission -SourceNode $SourceNode -TargetNode $TargetNode -DomainInfo $DomainInfo
}