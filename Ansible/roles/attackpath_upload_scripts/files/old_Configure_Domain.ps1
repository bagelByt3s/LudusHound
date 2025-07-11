[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [switch]$AttackPath,
    
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# Import required modules
Import-Module ActiveDirectory

# Read the JSON file
try {
    $jsonContent = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
    Write-Host "Successfully loaded JSON file: $FilePath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to read JSON file: $_"
    exit 1
}

# Extract nodes and edges from JSON
$nodes = $jsonContent.data.nodes
$edges = $jsonContent.data.edges

# Create a hashtable to store created objects for later reference
$createdObjects = @{}

# Extract domain information from labels
function Get-DomainInfo {
    param([string]$label)
    
    if ($label -match '@(.+)$') {
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

# Get domain info from the first label that contains it
$domainInfo = $null
foreach ($nodeId in $nodes.PSObject.Properties.Name) {
    $node = $nodes.$nodeId
    $domainInfo = Get-DomainInfo -label $node.label
    if ($domainInfo) { break }
}

if (-not $domainInfo) {
    Write-Error "Could not determine domain from JSON data"
    exit 1
}

Write-Host "Using domain: $($domainInfo.Domain)" -ForegroundColor Cyan
Write-Host "Domain DN: $($domainInfo.DN)" -ForegroundColor Cyan

# Process each node
foreach ($nodeId in $nodes.PSObject.Properties.Name) {
    $node = $nodes.$nodeId
    
    switch ($node.kind) {
        "User" {
            try {
                # Extract username without domain
                $samAccountName = $node.label -replace '@.*$'
                $displayName = $samAccountName
                
                # Check if user already exists
                $existingUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" -ErrorAction SilentlyContinue
                
                if (-not $existingUser) {
                    # Create the user
                    $userParams = @{
                        Name = $displayName
                        SamAccountName = $samAccountName
                        UserPrincipalName = $node.label
                        DisplayName = $displayName
                        Enabled = $true
                        AccountPassword = (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
                        ChangePasswordAtLogon = $true
                        Path = "CN=Users,$($domainInfo.DN)"
                    }
                    
                    New-ADUser @userParams
                    Write-Host "Created user: $($node.label)" -ForegroundColor Green
                }
                else {
                    Write-Host "User already exists: $($node.label)" -ForegroundColor Yellow
                }
                
                $createdObjects[$nodeId] = Get-ADUser -Identity $samAccountName
            }
            catch {
                Write-Error "Failed to create user '$($node.label)': $_"
            }
        }
        
        "OU" {
            try {
                # Extract OU name
                $ouName = $node.label -replace '@.*$'
                
                # Check if OU already exists
                $existingOU = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -ErrorAction SilentlyContinue
                
                if (-not $existingOU) {
                    # Create the OU
                    $ouParams = @{
                        Name = $ouName
                        Path = $domainInfo.DN
                        Description = "Created by Attack Path script"
                    }
                    
                    New-ADOrganizationalUnit @ouParams
                    Write-Host "Created OU: $ouName" -ForegroundColor Green
                }
                else {
                    Write-Host "OU already exists: $ouName" -ForegroundColor Yellow
                }
                
                $createdObjects[$nodeId] = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" | Select-Object -First 1
            }
            catch {
                Write-Error "Failed to create OU '$($node.label)': $_"
            }
        }
        
        "Group" {
            try {
                # Extract group name
                $groupName = $node.label -replace '@.*$'
                
                # Check if group already exists
                $existingGroup = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                
                if (-not $existingGroup) {
                    # Create the group
                    $groupParams = @{
                        Name = $groupName
                        SamAccountName = $groupName
                        GroupScope = "Global"
                        GroupCategory = "Security"
                        Path = "CN=Users,$($domainInfo.DN)"
                        Description = "Created by Attack Path script"
                    }
                    
                    New-ADGroup @groupParams
                    Write-Host "Created group: $groupName" -ForegroundColor Green
                }
                else {
                    Write-Host "Group already exists: $groupName" -ForegroundColor Yellow
                }
                
                $createdObjects[$nodeId] = Get-ADGroup -Identity $groupName
            }
            catch {
                Write-Error "Failed to create group '$($node.label)': $_"
            }
        }
        
        "GPO" {
            try {
                # Extract GPO name
                $gpoName = $node.label -replace '@.*$'
                
                # Check if GPO already exists
                $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                
                if (-not $existingGPO) {
                    # Create the GPO
                    $gpo = New-GPO -Name $gpoName -Comment "Created by Attack Path script"
                    Write-Host "Created GPO: $gpoName" -ForegroundColor Green
                }
                else {
                    Write-Host "GPO already exists: $gpoName" -ForegroundColor Yellow
                    $gpo = $existingGPO
                }
                
                $createdObjects[$nodeId] = $gpo
            }
            catch {
                Write-Error "Failed to create GPO '$($node.label)': $_"
            }
        }
        
        "Computer" {
            Write-Host "Skipping computer object: $($node.label)" -ForegroundColor Cyan
        }
    }
}

# Process relationships (edges)
foreach ($edge in $edges) {
    switch ($edge.kind) {
        "MemberOf" {
            try {
                # Add user to group
                $sourceNode = $nodes.$($edge.source)
                $targetNode = $nodes.$($edge.target)
                
                if ($sourceNode.kind -eq "User" -and $targetNode.kind -eq "Group") {
                    $samAccountName = $sourceNode.label -replace '@.*$'
                    $groupName = $targetNode.label -replace '@.*$'
                    
                    Add-ADGroupMember -Identity $groupName -Members $samAccountName
                    Write-Host "Added user '$samAccountName' to group '$groupName'" -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to add membership: $_"
            }
        }
        
        "GenericWrite" {
            try {
                # Set permissions on GPO
                $sourceNode = $nodes.$($edge.source)
                $targetNode = $nodes.$($edge.target)
                
                if ($sourceNode.kind -eq "Group" -and $targetNode.kind -eq "GPO") {
                    $groupName = $sourceNode.label -replace '@.*$'
                    $gpoName = $targetNode.label -replace '@.*$'
                    
                    $group = Get-ADGroup -Identity $groupName
                    $gpo = Get-GPO -Name $gpoName
                    
                    # Grant GenericWrite permission
                    $gpoPath = "CN={" + $gpo.Id + "},CN=Policies,CN=System,$($domainInfo.DN)"
                    $acl = Get-Acl -Path "AD:\$gpoPath"
                    
                    # Create ACE for GenericWrite
                    $identity = New-Object System.Security.Principal.SecurityIdentifier($group.SID)
                    $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                    $type = [System.Security.AccessControl.AccessControlType]::Allow
                    
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type)
                    $acl.AddAccessRule($ace)
                    
                    Set-Acl -Path "AD:\$gpoPath" -AclObject $acl
                    Write-Host "Granted GenericWrite permission to '$groupName' on GPO '$gpoName'" -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to set GenericWrite permission: $_"
            }
        }
        
        "GPLink" {
            try {
                # Link GPO to OU
                $sourceNode = $nodes.$($edge.source)
                $targetNode = $nodes.$($edge.target)
                
                if ($sourceNode.kind -eq "GPO" -and $targetNode.kind -eq "OU") {
                    $gpoName = $sourceNode.label -replace '@.*$'
                    $ouName = $targetNode.label -replace '@.*$'
                    
                    $gpo = Get-GPO -Name $gpoName
                    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" | Select-Object -First 1
                    
                    New-GPLink -Name $gpoName -Target $ou.DistinguishedName
                    Write-Host "Linked GPO '$gpoName' to OU '$ouName'" -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to link GPO: $_"
            }
        }
        
        "Contains" {
            try {
                # Move computer to OU (assuming computer already exists)
                $sourceNode = $nodes.$($edge.source)
                $targetNode = $nodes.$($edge.target)
                
                if ($sourceNode.kind -eq "OU" -and $targetNode.kind -eq "Computer") {
                    $ouName = $sourceNode.label -replace '@.*$'
                    $computerName = $targetNode.label
                    
                    # Get the OU and computer objects
                    $ou = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" | Select-Object -First 1
                    $computer = Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction SilentlyContinue
                    
                    if ($computer -and $ou) {
                        # Move the computer to the OU
                        Move-ADObject -Identity $computer.DistinguishedName -TargetPath $ou.DistinguishedName
                        Write-Host "Moved computer '$computerName' to OU '$ouName'" -ForegroundColor Green
                    }
                    else {
                        if (-not $computer) {
                            Write-Warning "Computer '$computerName' not found in AD"
                        }
                        if (-not $ou) {
                            Write-Warning "OU '$ouName' not found in AD"
                        }
                    }
                }
            }
            catch {
                Write-Error "Failed to process Contains relationship: $_"
            }
        }
    }
}

Write-Host "`nScript execution completed!" -ForegroundColor Green