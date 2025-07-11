param(
    [string]$f,         # File path
    [int]$c = 0,        # Count of entries to process (0 means all entries)
    [switch]$fullSend   # Full send flag (process all entries)
)

# Check if the file path is provided
if (-not $f) {
    Write-Host "Please provide the path to the JSON file using the -f argument."
    exit
}

# Check if the file exists
if (-not (Test-Path $f)) {
    Write-Host "The file '$f' does not exist."
    exit
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\GenericWrite"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Read and parse the JSON file
try {
    $jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json
} catch {
    Write-Host "Failed to parse the JSON file. Please check the file format."
    exit
}

# Determine how many entries to process
if ($fullSend) {
    # If -fullSend is provided, process all entries
    $entriesToProcess = $jsonContent
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $entriesToProcess = $jsonContent[0..($c - 1)]  # Get the first $c entries
} else {
    # If neither -fullSend nor a valid -c is provided, process all entries
    $entriesToProcess = $jsonContent
}

# Import Active Directory module
Import-Module ActiveDirectory
# Import the GroupPolicy module for GPO operations
Import-Module GroupPolicy

# Add the DirectoryServices assembly for ACL manipulation
Add-Type -AssemblyName System.DirectoryServices

# Define exclusion filters
$exclusionFilters = @(
    "Account Operators",
    "Domain Admins",
    "Enterprise Domain Controllers",
    "Enterprise Admins",
    "Enterprise Key Admins",
    "Domain Controller"
)

# Start logging to the log file
Start-Transcript -Path $logFile

# Function to grant GenericWrite permission for GPOs specifically
function Grant-GPOGenericWritePermission {
    param (
        [string]$gpoName,
        [string]$domain,
        [System.Security.Principal.SecurityIdentifier]$sourceSid,
        [string]$sourceDisplay,
        [System.Management.Automation.PSCredential]$credential = $null
    )
    
    try {
        # First clean up the GPO name if it contains domain info
        if ($gpoName -match '@') {
            $gpoName = $gpoName.Split('@')[0]
        }
        
        Write-Host "Attempting to set GPO permissions for GPO: $gpoName in domain: $domain" -ForegroundColor Cyan
        
        # Get the current domain
        $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
        $isCrossDomain = ($domain -ne $currentDomain)
        
        # Create credential for cross-domain if needed
        if ($isCrossDomain -and -not $credential) {
            $username = "DomainAdmin@$domain"
            $securePassword = ConvertTo-SecureString "password" -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
            Write-Host "Created credentials for cross-domain operation with $username" -ForegroundColor Yellow
        }
        
        # Get the GPO object with appropriate credentials if cross-domain
        if ($isCrossDomain -and $credential) {
            # For cross-domain GPOs, we need to use the DirectoryEntry approach directly
            # First, get the GPO GUID if possible
            Write-Host "Using cross-domain approach for GPO access" -ForegroundColor Cyan
            
            # Try to get the GPO from the remote domain
            try {
                $gpo = Get-GPO -Name $gpoName -Domain $domain -Server $domain -ErrorAction Stop
                $gpoGuid = $gpo.Id.ToString()
            } catch {
                # If we can't get the GUID from Get-GPO, try known GUIDs for default policies
                Write-Host "Could not get GPO directly, trying known GUIDs..." -ForegroundColor Yellow
                
                # Known GUIDs for default policies
                if ($gpoName -eq "Default Domain Policy") {
                    $gpoGuid = "31B2F340-016D-11D2-945F-00C04FB984F9"
                } elseif ($gpoName -eq "Default Domain Controllers Policy") {
                    $gpoGuid = "6AC1786C-016F-11D2-945F-00C04FB984F9"
                } else {
                    throw "Cannot determine GPO GUID for $gpoName"
                }
            }
            
            # Construct the GPO path in AD
            $domainComponents = $domain -split '\.' | ForEach-Object { "DC=$_" }
            $domainPath = $domainComponents -join ','
            $gpoPath = "CN={$gpoGuid},CN=Policies,CN=System,$domainPath"
            
            Write-Host "GPO AD Path: $gpoPath" -ForegroundColor Cyan
            
            # Create DirectoryEntry with credentials
            $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
            $targetDe = New-Object System.DirectoryServices.DirectoryEntry(
                "LDAP://$domain/$gpoPath",
                $credential.UserName,
                $credential.GetNetworkCredential().Password,
                $authType
            )
            
            # Get the security descriptor directly
            Write-Host "Accessing security descriptor directly via DirectoryEntry" -ForegroundColor Cyan
            $sd = $targetDe.ObjectSecurity
            
            # Create a new access rule for GenericWrite permission
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
            $inheritedObjectType = [guid]::Empty
            
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sourceSid,
                $adRights,
                $type,
                $inheritanceType,
                $inheritedObjectType
            )
            
            # Add the access rule to the security descriptor
            $sd.AddAccessRule($ace)
            
            # Set the modified security descriptor back to the object
            $targetDe.ObjectSecurity = $sd
            $targetDe.CommitChanges()
        }
        else {
            # For same-domain GPOs, use the standard approach
            $gpo = Get-GPO -Name $gpoName -Domain $domain -ErrorAction Stop
            
            # Get the AD object for the GPO using its ID
            $gpoGuid = $gpo.Id.ToString()
            
            # Construct the GPO path in AD
            $domainComponents = $domain -split '\.' | ForEach-Object { "DC=$_" }
            $domainPath = $domainComponents -join ','
            $gpoPath = "CN={$gpoGuid},CN=Policies,CN=System,$domainPath"
            
            Write-Host "GPO AD Path: $gpoPath" -ForegroundColor Cyan
            
            # Get the ACL, add the permission, and set it back
            $acl = Get-Acl -Path "AD:$gpoPath"
            
            # Create a new access rule for GenericWrite permission
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sourceSid,
                $adRights,
                $type
            )
            
            # Add the access rule to the ACL
            $acl.AddAccessRule($ace)
            
            # Set the modified ACL back to the GPO object
            Set-Acl -Path "AD:$gpoPath" -AclObject $acl
        }
        
        Write-Host "Successfully granted GenericWrite permissions for $sourceDisplay on GPO '$gpoName'" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error granting GPO GenericWrite permissions to $sourceDisplay - $($_)" -ForegroundColor Red
        
        # Additional error information for troubleshooting
        if ($Error.Count -gt 0) {
            Write-Host "Exception details: $($Error[0].Exception.GetType().FullName)" -ForegroundColor Yellow
            Write-Host "Error category: $($Error[0].CategoryInfo.Category)" -ForegroundColor Yellow
        }
        
        return $false
    }
}

# Function to grant GenericWrite permission (for non-GPO objects)
function Grant-GenericWritePermission {
    param (
        [System.DirectoryServices.DirectoryEntry]$targetObject,
        [System.Security.Principal.SecurityIdentifier]$sourceSid,
        [string]$sourceDisplay,
        [string]$targetDN = ""
    )
    
    try {
        # Ensure the directory entry is connected
        if (-not $targetObject.Path) {
            Write-Host "Invalid DirectoryEntry object - no path" -ForegroundColor Red
            return $false
        }
        
        # Display what we're working with
        Write-Host "Working with target path: $($targetObject.Path)" -ForegroundColor Cyan
        
        try {
            # Try to access the object to ensure it's really there
            $null = $targetObject.RefreshCache()
        }
        catch {
            Write-Host "Error accessing DirectoryEntry: $_" -ForegroundColor Red
            Write-Host "Will attempt to continue anyway..." -ForegroundColor Yellow
        }
        
        # Get the ACL for the target object
        $acl = $targetObject.ObjectSecurity
        if (-not $acl) {
            Write-Host "Could not get security descriptor for the target object" -ForegroundColor Red
            return $false
        }
        
        # Create a new access rule for GenericWrite permission
        $identity = $sourceSid
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
        $type = [System.Security.AccessControl.AccessControlType]::Allow
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
        $inheritedObjectType = [guid]::Empty
        
        Write-Host "Creating access rule with SID: $sourceSid" -ForegroundColor Cyan
        
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $identity,
            $adRights,
            $type,
            $inheritanceType,
            $inheritedObjectType
        )
        
        # Add the access rule to the ACL
        $acl.AddAccessRule($ace)
        
        # Set the modified ACL back to the target object
        $targetObject.ObjectSecurity = $acl
        $targetObject.CommitChanges()
        
        # Use the provided DN if available, otherwise get it from the object
        $displayDN = if ($targetDN) { $targetDN } else { $targetObject.distinguishedName.Value }
        
        Write-Host "Successfully granted GenericWrite permissions for $sourceDisplay on $displayDN" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error granting GenericWrite permissions to $sourceDisplay - $($_)" -ForegroundColor Red
        
        # Additional error information for troubleshooting
        if ($Error.Count -gt 0) {
            Write-Host "Exception details: $($Error[0].Exception.GetType().FullName)" -ForegroundColor Yellow
            Write-Host "Error category: $($Error[0].CategoryInfo.Category)" -ForegroundColor Yellow
        }
        
        return $false
    }
}

# Function to find computer object by name
function Find-ComputerObject {
    param (
        [string]$computerName,
        [string]$domain
    )
    
    Write-Host "Searching for computer: $computerName in domain $domain" -ForegroundColor Cyan
    
    # Strip off the domain part if it's included
    if ($computerName -like "*@*") {
        $computerName = $computerName.Split("@")[0]
    }
    
    try {
        # First attempt: direct name match
        $computer = Get-ADComputer -Filter {Name -eq $computerName} -Properties * -ErrorAction SilentlyContinue
        if ($computer) {
            Write-Host "Found computer by exact name match" -ForegroundColor Green
            return $computer
        }
        
        # Second attempt: try with $ suffix for SAM account name
        $computer = Get-ADComputer -Filter {SamAccountName -eq "$computerName$"} -Properties * -ErrorAction SilentlyContinue
        if ($computer) {
            Write-Host "Found computer by SAM account name with $ suffix" -ForegroundColor Green
            return $computer
        }
        
        # Third attempt: wildcard search
        $computer = Get-ADComputer -Filter {Name -like "$computerName*"} -Properties * -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($computer) {
            Write-Host "Found computer by wildcard search: $($computer.Name)" -ForegroundColor Green
            return $computer
        }
        
        # Fourth attempt: try in Computers container
        $baseDN = ($domain -split '\.') | ForEach-Object { "DC=$_" }
        $baseDN = $baseDN -join ','
        
        $computerFilter = "(&(objectClass=computer)(|(name=$computerName)(cn=$computerName)))"
        $computerObjects = Get-ADObject -LDAPFilter $computerFilter -SearchBase "CN=Computers,$baseDN" -Properties * -ErrorAction SilentlyContinue
        
        if ($computerObjects) {
            Write-Host "Found computer in Computers container" -ForegroundColor Green
            return $computerObjects[0]
        }
        
        # Fifth attempt: search in the entire domain
        $computerObjects = Get-ADObject -LDAPFilter $computerFilter -SearchBase $baseDN -Properties * -ErrorAction SilentlyContinue
        
        if ($computerObjects) {
            Write-Host "Found computer somewhere in the domain" -ForegroundColor Green
            return $computerObjects[0]
        }
        
        Write-Host "Computer not found using any method" -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Host "Error searching for computer: $_" -ForegroundColor Red
        return $null
    }
}

# Function to extract GPO name from DN or target
function Extract-GPOName {
    param (
        [string]$targetName,
        [string]$targetDN
    )
    
    # Strip domain suffix if present
    if ($targetName -match '@') {
        $targetName = $targetName.Split('@')[0]
    }
    
    # Check if the target DN contains "CN=Policies,CN=System"
    if ($targetDN -match 'CN=\{(.*?)\},CN=Policies,CN=System') {
        # Try to get the GPO by its GUID
        $gpoGuid = $matches[1]
        try {
            $gpo = Get-GPO -Guid $gpoGuid -ErrorAction SilentlyContinue
            if ($gpo) {
                return $gpo.DisplayName
            }
        }
        catch {
            # Just continue with other methods
        }
    }
    
    # If we have a target name and it looks like a GPO name
    if ($targetName -and ($targetName -like "*GPO*" -or $targetName -like "*Policy*")) {
        return $targetName
    }
    
    # If we have a target name but it doesn't contain GPO or Policy, assume it's still a GPO name
    if ($targetName) {
        return $targetName
    }
    
    # If we have a DN but couldn't extract the name, try to get the CN
    if ($targetDN -match 'CN=(.*?),') {
        return $matches[1]
    }
    
    return $null
}

# Process each entry and configure permissions
Write-Host "Processing GenericWrite permissions..."
Write-Host "========================================"
$filteredCount = 0
$successCount = 0
$errorCount = 0

foreach ($entry in $entriesToProcess) {
    # Skip entries where source contains any of the exclusion filters
    $shouldExclude = $false
    foreach ($filter in $exclusionFilters) {
        if ($entry.source -like "*$filter*") {
            $shouldExclude = $true
            $filteredCount++
            break
        }
    }
    
    # Continue to next entry if this one should be excluded
    if ($shouldExclude) {
        Write-Host "Skipping filtered entry: $($entry.source) -> $($entry.target)" -ForegroundColor Gray
        continue
    }
    
    # Output information for this entry
    Write-Host "Source: $($entry.source)"
    Write-Host "Source Domain: $($entry.sourceDomain)"
    Write-Host "Relationship: $($entry.relationship)"
    Write-Host "Target: $($entry.target)"
    Write-Host "Target Domain: $($entry.targetDomain)"
    
    # Get the current domain
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    
    # Check if we need to use alternate credentials for cross-domain operations
    $useCredential = $false
    $credential = $null
    
    if ($entry.targetDomain -ne $currentDomain) {
        Write-Host "Target domain is different from current domain, will use DomainAdmin credentials" -ForegroundColor Yellow
        $username = "DomainAdmin@$($entry.targetDomain)"
        $password = ConvertTo-SecureString "password" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($username, $password)
        $useCredential = $true
    }
    
    # Get source object
    $sourceObject = $null
    
    # Try to get source object first by DN if available
    if ($entry.sourceDN) {
        try {
            Write-Host "Attempting to find source directly by DN: $($entry.sourceDN)" -ForegroundColor Cyan
            $sourceObject = Get-ADObject -Identity $entry.sourceDN -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Error finding source by DN: $_" -ForegroundColor Yellow
        }
    }
    
    # If not found by DN, try by name
    if (-not $sourceObject) {
        try {
            Write-Host "Attempting to find source by name: $($entry.source)" -ForegroundColor Cyan
            # Extract the name part if it contains @domain
            $sourceName = $entry.source -replace '@.*$', ''
            
            # Try user lookup
            $sourceObject = Get-ADUser -Filter "Name -eq '$sourceName' -or SamAccountName -eq '$sourceName'" -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            
            # Try group lookup if user lookup failed
            if (-not $sourceObject) {
                $sourceObject = Get-ADGroup -Filter "Name -eq '$sourceName' -or SamAccountName -eq '$sourceName'" -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Host "Error finding source by name: $_" -ForegroundColor Yellow
        }
    }
    
    # Check if the target is a GPO
    $isGpo = $false
    $gpoName = $null
    
    # First, clean up the target name if it has a domain suffix
    $cleanTargetName = $entry.target
    if ($cleanTargetName -match '@') {
        $cleanTargetName = $cleanTargetName.Split('@')[0]
    }
    
    if ($cleanTargetName -like "*GPO*" -or $cleanTargetName -like "*Policy*" -or 
        $entry.targetDN -like "*CN=Policies,CN=System*") {
        $isGpo = $true
        $gpoName = Extract-GPOName -targetName $cleanTargetName -targetDN $entry.targetDN
        Write-Host "Target appears to be a GPO: $gpoName" -ForegroundColor Cyan
    }
    
    # If it's a GPO, use the specialized GPO function
    if ($isGpo -and $gpoName -and $sourceObject) {
        Write-Host "Processing GPO permissions using specialized method..." -ForegroundColor Cyan
        
        # Pass credentials if we're working cross-domain
        if ($useCredential) {
            $result = Grant-GPOGenericWritePermission -gpoName $gpoName -domain $entry.targetDomain -sourceSid $sourceObject.objectSid -sourceDisplay $entry.source -credential $credential
        } else {
            $result = Grant-GPOGenericWritePermission -gpoName $gpoName -domain $entry.targetDomain -sourceSid $sourceObject.objectSid -sourceDisplay $entry.source
        }
        
        if ($result) {
            $successCount++
        }
        else {
            $errorCount++
        }
        
        Write-Host "----------------------------------------"
        continue  # Skip to the next entry
    }
    
    # For non-GPO objects, continue with the standard approach
    
    # Get target object
    $targetObject = $null
    $targetDe = $null
    
    # Determine if the target is likely a computer
    $isComputerTarget = $false
    if ($entry.target -match '^\w+\d*$' -or $entry.targetDN -match 'CN=[^,]+,CN=Computers,') {
        $isComputerTarget = $true
        Write-Host "Target appears to be a computer object" -ForegroundColor Cyan
    }
    
    # First try by DN if provided
    if ($entry.targetDN) {
        try {
            Write-Host "Attempting to find target directly by DN: $($entry.targetDN)" -ForegroundColor Cyan
            
            # Try with Get-ADObject first
            if (-not $useCredential) {
                $targetObject = Get-ADObject -Identity $entry.targetDN -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
                
                if ($targetObject) {
                    Write-Host "Found target object using Get-ADObject" -ForegroundColor Green
                    $targetDe = [ADSI]"LDAP://$($entry.targetDN)"
                }
            }
            
            # If that failed or we're dealing with cross-domain, try DirectoryEntry
            if (-not $targetObject -or $useCredential) {
                if ($useCredential) {
                    # For cross-domain objects with credentials
                    $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
                    $targetServer = $entry.targetDomain  # Use domain directly
                    
                    Write-Host "Using server: $targetServer with credentials" -ForegroundColor Cyan
                    
                    $targetDe = New-Object System.DirectoryServices.DirectoryEntry(
                        "LDAP://$targetServer/$($entry.targetDN)",
                        $credential.UserName,
                        $credential.GetNetworkCredential().Password,
                        $authType
                    )
                }
                else {
                    # For same-domain objects
                    $targetDe = [ADSI]"LDAP://$($entry.targetDN)"
                }
                
                # Create a minimal object for reference if needed
                if (-not $targetObject -and $targetDe.Path) {
                    $targetObject = [PSCustomObject]@{
                        DistinguishedName = $entry.targetDN
                        ObjectSid = $null
                    }
                    Write-Host "Created reference object for target" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "Error finding target by DN: $_" -ForegroundColor Yellow
        }
    }
    
    # If not found by DN and target appears to be a computer, try special computer lookup
    if ((-not $targetObject -or -not $targetDe) -and $isComputerTarget) {
        try {
            $computer = Find-ComputerObject -computerName $entry.target.Split("@")[0] -domain $entry.targetDomain
            
            if ($computer) {
                $targetObject = $computer
                $targetDN = $computer.DistinguishedName
                
                Write-Host "Found computer object: $targetDN" -ForegroundColor Green
                
                if ($useCredential) {
                    # For cross-domain objects with credentials
                    $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
                    $targetServer = $entry.targetDomain
                    
                    $targetDe = New-Object System.DirectoryServices.DirectoryEntry(
                        "LDAP://$targetServer/$targetDN",
                        $credential.UserName,
                        $credential.GetNetworkCredential().Password,
                        $authType
                    )
                }
                else {
                    # For same-domain objects
                    $targetDe = [ADSI]"LDAP://$targetDN"
                }
            }
        }
        catch {
            Write-Host "Error in computer lookup: $_" -ForegroundColor Red
        }
    }
    
    # If still not found, try some standard approaches
    if (-not $targetObject -or -not $targetDe) {
        try {
            Write-Host "Trying standard lookup methods for target" -ForegroundColor Cyan
            $targetName = $entry.target -replace '@.*$', ''
            
            # Try with Get-ADObject first (users, groups, etc.)
            $target = Get-ADObject -Filter "Name -eq '$targetName' -or SamAccountName -eq '$targetName'" -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            
            if ($target) {
                $targetObject = $target
                $targetDN = $target.DistinguishedName
                
                Write-Host "Found target object: $targetDN" -ForegroundColor Green
                
                if ($useCredential) {
                    # For cross-domain objects with credentials
                    $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
                    $targetServer = $entry.targetDomain
                    
                    $targetDe = New-Object System.DirectoryServices.DirectoryEntry(
                        "LDAP://$targetServer/$targetDN",
                        $credential.UserName,
                        $credential.GetNetworkCredential().Password,
                        $authType
                    )
                }
                else {
                    # For same-domain objects
                    $targetDe = [ADSI]"LDAP://$targetDN"
                }
            }
        }
        catch {
            Write-Host "Error in standard lookup: $_" -ForegroundColor Red
        }
    }
    
    # Determine target type (simple approach)
    $targetType = "Unknown"
    if ($targetObject) {
        if ($isComputerTarget -or $targetObject.objectClass -eq "computer") {
            $targetType = "Computer"
        }
        elseif ($entry.target -like "*POLICY*" -or $entry.targetDN -like "*CN=POLICIES,CN=SYSTEM*") {
            $targetType = "Group Policy Object"
        }
        elseif ($targetObject.objectClass) {
            $targetType = $targetObject.objectClass
        }
    }
    
    Write-Host "Target Type: $targetType"
    
    # Attempt to configure permissions if we have the source and target
    if ($sourceObject -and $targetDe -and $targetDe.Path) {
        Write-Host "Found both source and target objects. Configuring GenericWrite permission..." -ForegroundColor Cyan
        
        Write-Host "Source Object: $($sourceObject.DistinguishedName)" -ForegroundColor Green
        if ($targetObject -and $targetObject.DistinguishedName) {
            Write-Host "Target DN: $($targetObject.DistinguishedName)" -ForegroundColor Green
        }
        else {
            Write-Host "Target Path: $($targetDe.Path)" -ForegroundColor Green
        }
        
        # Grant GenericWrite permission
        $targetDisplayDN = if ($targetObject -and $targetObject.DistinguishedName) { $targetObject.DistinguishedName } else { $entry.targetDN }
        $result = Grant-GenericWritePermission -targetObject $targetDe -sourceSid $sourceObject.objectSid -sourceDisplay $entry.source -targetDN $targetDisplayDN
        
        if ($result) {
            $successCount++
        }
        else {
            $errorCount++
        }
    }
    else {
        if (-not $sourceObject) {
            Write-Host "Source object not found in AD: $($entry.source)" -ForegroundColor Yellow
            if ($entry.sourceDN) {
                Write-Host "Source DN: $($entry.sourceDN)" -ForegroundColor Yellow
            }
        }
        if (-not $targetDe -or -not $targetDe.Path) {
            Write-Host "Target object not found or not accessible: $($entry.target)" -ForegroundColor Yellow
            if ($entry.targetDN) {
                Write-Host "Target DN: $($entry.targetDN)" -ForegroundColor Yellow
            }
        }
        $errorCount++
    }
    
    Write-Host "----------------------------------------"
}

Write-Host "Total entries processed: $($entriesToProcess.Count - $filteredCount) of $($jsonContent.Count) (filtered out $filteredCount entries)"
Write-Host "Successfully configured: $successCount permissions"
Write-Host "Failed to configure: $errorCount permissions"
Write-Host "Log file created at: $logFile"

# Stop transcript logging
Stop-Transcript