# Set Constrained Delegation Permission Script
# Save as: Set-ConstrainedDelegationPermission.ps1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$SourceNode,
    
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$TargetNode,
    
    [Parameter(Mandatory=$true)]
    [hashtable]$DomainInfo
)

# Import Active Directory module if not already loaded
if (!(Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    Import-Module ActiveDirectory -ErrorAction Stop
}

try {
    Write-Host "Processing constrained delegation from $($SourceNode.label) to $($TargetNode.label)" -ForegroundColor Green
    
    # Extract the actual names from the labels
    # For users: AMY.ANDERSON@GHOST.LOCAL -> AMY.ANDERSON
    # For computers: TITAN.GHOST.LOCAL -> TITAN
    $sourceName = if ($SourceNode.kind -eq "User") { ($SourceNode.label -split '@')[0] } else { ($SourceNode.label -split '\.')[0] }
    $targetName = if ($TargetNode.kind -eq "User") { ($TargetNode.label -split '@')[0] } else { ($TargetNode.label -split '\.')[0] }
    
    Write-Host "Source: $sourceName ($($SourceNode.kind)), Target: $targetName ($($TargetNode.kind))" -ForegroundColor Cyan
    
    # Get source object based on kind
    $sourceADObject = if ($SourceNode.kind -eq "User") {
        Get-ADUser -Identity $sourceName -Properties servicePrincipalName -ErrorAction Stop
    } else {
        Get-ADComputer -Identity $sourceName -Properties servicePrincipalName -ErrorAction Stop
    }
    
    # Get target object and SPNs based on kind
    $targetADObject = if ($TargetNode.kind -eq "User") {
        Get-ADUser -Identity $targetName -Properties servicePrincipalName -ErrorAction Stop
    } else {
        Get-ADComputer -Identity $targetName -Properties servicePrincipalName -ErrorAction Stop
    }
    
    $targetSPNs = if ($targetADObject.servicePrincipalName) { $targetADObject.servicePrincipalName } else { @() }
    
    # Enable constrained delegation on source object
    Set-ADAccountControl -Identity $sourceADObject.DistinguishedName -TrustedForDelegation $false -TrustedToAuthForDelegation $true
    
    # Configure delegation targets
    $spnsToAdd = if ($targetSPNs.Count -gt 0) {
        Write-Host "Setting delegation to existing SPNs: $($targetSPNs -join ', ')" -ForegroundColor Gray
        $targetSPNs
    } else {
        # Create default SPNs based on target type
        $defaultSPNs = if ($TargetNode.kind -eq "User") {
            @("HTTP/$targetName")
        } else {
            @("HOST/$targetName", "HTTP/$targetName", "CIFS/$targetName")
        }
        Write-Host "Setting delegation to default SPNs: $($defaultSPNs -join ', ')" -ForegroundColor Gray
        $defaultSPNs
    }
    
    # Add delegation SPNs to source object
    if ($SourceNode.kind -eq "User") {
        Set-ADUser -Identity $sourceADObject.DistinguishedName -Add @{'msDS-AllowedToDelegateTo' = [string[]]$spnsToAdd}
    } else {
        Set-ADComputer -Identity $sourceADObject.DistinguishedName -Add @{'msDS-AllowedToDelegateTo' = [string[]]$spnsToAdd}
    }
    
    Write-Host "Successfully configured constrained delegation from $sourceName to $targetName" -ForegroundColor Green
    
    # Display current delegation settings
    Write-Host "`nCurrent delegation settings:" -ForegroundColor Magenta
    $delegationSettings = if ($SourceNode.kind -eq "User") {
        Get-ADUser -Identity $sourceADObject.DistinguishedName -Properties 'msDS-AllowedToDelegateTo', userAccountControl
    } else {
        Get-ADComputer -Identity $sourceADObject.DistinguishedName -Properties 'msDS-AllowedToDelegateTo', userAccountControl
    }
    
    # Check TrustedToAuthForDelegation bit (0x1000000)
    $trustedToAuthForDelegation = ($delegationSettings.userAccountControl -band 0x1000000) -ne 0
    Write-Host "TrustedToAuthForDelegation: $trustedToAuthForDelegation" -ForegroundColor Gray
    
    if ($delegationSettings.'msDS-AllowedToDelegateTo') {
        Write-Host "Allowed to delegate to: $($delegationSettings.'msDS-AllowedToDelegateTo' -join ', ')" -ForegroundColor Gray
    }

} catch {
    Write-Error "Failed to configure constrained delegation from $($SourceNode.label) to $($TargetNode.label): $($_.Exception.Message)"
    throw
}