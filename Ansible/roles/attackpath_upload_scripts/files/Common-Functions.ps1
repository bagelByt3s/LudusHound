# Common Functions Module for Attack Path Scripts
# Save as: Common-Functions.ps1

function Get-DomainInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Label
    )
    
    if ($Label -match '@(.+)$') {
        $domain = $matches[1]
        $domainDN = "DC=" + ($domain -replace '\.',',DC=')
        return @{
            Domain = $domain
            DN = $domainDN
            NetBIOSName = ($domain -split '\.')[0]
        }
    }
    return $null
}

function Get-DomainFromNodes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Nodes
    )
    
    $domainInfo = $null
    foreach ($nodeId in $Nodes.PSObject.Properties.Name) {
        $node = $Nodes.$nodeId
        $domainInfo = Get-DomainInfo -Label $node.label
        if ($domainInfo) { break }
    }
    return $domainInfo
}

#Export-ModuleMember -Function Get-DomainInfo, Get-DomainFromNodes