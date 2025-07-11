# Set GenericWrite Permission Script
# Save as: Set-GenericWritePermission.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

function Set-GenericWritePermission {
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
            # For computer objects, extract name without domain
            if ($targetName -match '^([^\.@]+)') {
                $computerName = $matches[1]
            } else {
                $computerName = $targetName
            }
            
            $targetName = $computerName
            Write-Host "Setting GenericWrite permission from '$sourceName' to computer '$targetName'" -ForegroundColor Cyan
        } else {
            # For other object types, remove domain suffix
            $targetName = $targetName -replace '@.*$'
            Write-Host "Setting GenericWrite permission from '$sourceName' to '$targetName'" -ForegroundColor Cyan
        }
        
        # Get source identity based on source kind
        switch ($SourceNode.kind) {
            "Group" {
                $sourceObject = Get-ADGroup -Identity $sourceName
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($sourceObject.SID)
            }
            "User" {
                $sourceObject = Get-ADUser -Identity $sourceName
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($sourceObject.SID)
            }
            "Computer" {
                if ($sourceName -match '^([^\.@]+)') {
                    $sourceComputerName = $matches[1]
                } else {
                    $sourceComputerName = $sourceName
                }
                
                $sourceObject = Get-ADComputer -Filter "Name -eq '$sourceComputerName'" -ErrorAction Stop
                
                if (-not $sourceObject) {
                    $sourceObject = Get-ADComputer -Filter "Name -like '$sourceComputerName*'" -ErrorAction Stop | Select-Object -First 1
                }
                
                if (-not $sourceObject) {
                    Write-Error "Computer object '$sourceComputerName' not found in Active Directory"
                    return
                }
                
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($sourceObject.SID)
            }
            "OU" {
                $sourceObject = Get-ADOrganizationalUnit -Filter "Name -eq '$sourceName'" -ErrorAction Stop
                
                if (-not $sourceObject) {
                    Write-Error "OU object '$sourceName' not found in Active Directory"
                    return
                }
                
                # OUs don't have SIDs, so find a group with the same name
                $ouGroup = Get-ADGroup -Filter "Name -eq '$sourceName'" -ErrorAction SilentlyContinue
                
                if (-not $ouGroup) {
                    Write-Warning "No security group found for OU '$sourceName'. GenericWrite permissions will not be applied."
                    return
                }
                
                $sourceIdentity = New-Object System.Security.Principal.SecurityIdentifier($ouGroup.SID)
            }
            default {
                Write-Warning "Unsupported source kind: $($SourceNode.kind)"
                return
            }
        }
        
        # Process target based on target kind
        switch ($TargetNode.kind) {
            "User" {
                $targetObject = Get-ADUser -Identity $targetName
                $targetDN = $targetObject.DistinguishedName
            }
            "Computer" {
                $targetObject = Get-ADComputer -Filter "Name -eq '$targetName'" -ErrorAction Stop
                
                if (-not $targetObject) {
                    $targetObject = Get-ADComputer -Filter "Name -like '$targetName*'" -ErrorAction Stop | Select-Object -First 1
                }
                
                if (-not $targetObject) {
                    Write-Error "Computer object '$targetName' not found in Active Directory"
                    return
                }
                
                $targetDN = $targetObject.DistinguishedName
            }
            "Group" {
                $targetObject = Get-ADGroup -Identity $targetName
                $targetDN = $targetObject.DistinguishedName
            }
            "OU" {
                $targetObject = Get-ADOrganizationalUnit -Filter "Name -eq '$targetName'" -ErrorAction Stop
                
                if (-not $targetObject) {
                    Write-Error "OU '$targetName' not found in Active Directory"
                    return
                }
                
                $targetDN = $targetObject.DistinguishedName
            }
            "GPO" {
                $gpo = Get-GPO -Name $targetName
                $targetDN = "CN={" + $gpo.Id + "},CN=Policies,CN=System,$($DomainInfo.DN)"
            }
            "Domain" {
                $targetDN = $DomainInfo.DN
            }
            default {
                Write-Warning "Unsupported target kind: $($TargetNode.kind)"
                return
            }
        }
        
        # Get the ACL of the target object
        $acl = Get-Acl -Path "AD:$targetDN"
        
        # Create a new access rule for GenericWrite
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        $type = [System.Security.AccessControl.AccessControlType]::Allow
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sourceIdentity, $adRights, $type)
        
        # Add the rule and set the ACL
        $acl.AddAccessRule($ace)
        Set-Acl -Path "AD:$targetDN" -AclObject $acl
        
        Write-Host "Granted GenericWrite permission from $($SourceNode.kind) '$sourceName' to $($TargetNode.kind) '$targetName'" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to set GenericWrite permission: $_"
        Write-Host "Source: $($SourceNode.label) ($($SourceNode.kind))" -ForegroundColor Yellow
        Write-Host "Target: $($TargetNode.label) ($($TargetNode.kind))" -ForegroundColor Yellow
    }
}

# Execute if running directly
if ($SourceNode -and $TargetNode -and $DomainInfo) {
    Set-GenericWritePermission -SourceNode $SourceNode -TargetNode $TargetNode -DomainInfo $DomainInfo
}