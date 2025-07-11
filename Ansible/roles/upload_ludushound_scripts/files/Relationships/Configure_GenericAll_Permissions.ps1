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
$logDir = ".\Log\GenericAll"
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

# Function to extract object name from various formats
function Get-CleanObjectName {
    param (
        [string]$objectName
    )
    
    # Remove domain suffix if present (object@domain.local or object.domain.local)
    if ($objectName -like "*@*") {
        $name = ($objectName -split '@')[0]
        Write-Host "  Extracted name from @-format: '$name' from '$objectName'" -ForegroundColor Cyan
        return $name
    }
    elseif ($objectName -like "*.*" -and $objectName -notlike "*CN=*" -and $objectName -notlike "*OU=*") {
        # Check if it's a FQDN format (has dots but not a DN)
        $parts = $objectName -split '\.'
        if ($parts.Count -gt 1) {
            # Take the first part as the computer name
            $name = $parts[0]
            Write-Host "  Extracted name from FQDN format: '$name' from '$objectName'" -ForegroundColor Cyan
            return $name
        }
    }
    
    # Return as-is if no special format detected
    return $objectName
}

# Function to determine object type using Active Directory cmdlets
function Get-ADObjectType {
    param (
        [string]$objectName,
        [string]$domain
    )
    
    try {
        # Clean the object name first
        $name = Get-CleanObjectName -objectName $objectName
        
        # Build the domain component string for the search base
        $baseDN = ($domain -split '\.') | ForEach-Object { "DC=$_" }
        $baseDN = $baseDN -join ','
        
        # Get all naming contexts (partitions) in the domain
        $rootDSE = Get-ADRootDSE
        $namingContexts = @($rootDSE.defaultNamingContext, $rootDSE.configurationNamingContext, $rootDSE.schemaNamingContext)
        
        # Create an array to store all identified object types
        $objectTypes = @()
        
        # Check if it's a container by searching all naming contexts
        foreach ($context in $namingContexts) {
            # Search for containers specifically, looking for the target object
            $containerFilter = "(&(objectClass=container)(|(cn=$name)(name=$name)))"
            $containerObject = Get-ADObject -LDAPFilter $containerFilter -SearchBase $context -SearchScope Subtree -Properties ObjectClass -ErrorAction SilentlyContinue
            
            if ($containerObject) {
                # If we found it, add Container and the naming context to the results
                $objectTypes += "Container ($($context.Split(',')[0].Replace('CN=','').Replace('DC=','')))"
            }
        }
        
        # Try with direct distinguished name if it looks like one
        if ($objectName -like "*CN=*,*" -or $objectName -like "*OU=*,*") {
            try {
                $directObject = Get-ADObject -Identity $objectName -Properties ObjectClass -ErrorAction SilentlyContinue
                if ($directObject) {
                    $objectTypes += "$($directObject.ObjectClass) (Direct)"
                }
            }
            catch {
                # Suppress direct lookup errors
            }
        }
        
        # Check for User object
        $adUser = Get-ADUser -Filter "Name -eq '$name' -or SamAccountName -eq '$name'" -ErrorAction SilentlyContinue
        if ($adUser) {
            $objectTypes += "User"
        }
        
        # Enhanced Computer object detection with multiple approaches
        try {
            # Standard approach - try exact name match first
            $adComputer = Get-ADComputer -Filter {(Name -eq $name)} -ErrorAction SilentlyContinue
            if ($adComputer) {
                $objectTypes += "Computer"
                Write-Host "  Found computer with exact name match: $($adComputer.Name)" -ForegroundColor Green
            }
            
            # Try with $ suffix for SAM account name
            if ("Computer" -notin $objectTypes) {
                $adComputer = Get-ADComputer -Filter {SamAccountName -eq "$name$"} -ErrorAction SilentlyContinue
                if ($adComputer) {
                    $objectTypes += "Computer"
                    Write-Host "  Found computer with SAM account name: $($adComputer.Name)" -ForegroundColor Green
                }
            }
            
            # Try DNS hostname matching
            if ("Computer" -notin $objectTypes) {
                $adComputer = Get-ADComputer -Filter {DNSHostName -like "$name*"} -ErrorAction SilentlyContinue
                if ($adComputer) {
                    $objectTypes += "Computer"
                    Write-Host "  Found computer with DNS hostname match: $($adComputer.Name)" -ForegroundColor Green
                }
            }
        }
        catch {
            # Fallback to LDAP filter for computers
            Write-Host "  Standard computer lookup failed, trying LDAP filter..." -ForegroundColor Yellow
            $computerFilter = "(&(objectClass=computer)(|(name=$name)(cn=$name)(dNSHostName=$name*)))"
            $computerObj = Get-ADObject -LDAPFilter $computerFilter -SearchBase $baseDN -Properties ObjectClass -ErrorAction SilentlyContinue
            
            if ($computerObj -and "Computer" -notin $objectTypes) {
                $objectTypes += "Computer"
                Write-Host "  Found computer with LDAP filter: $($computerObj.Name)" -ForegroundColor Green
            }
            
            # Broader search across all contexts
            if ("Computer" -notin $objectTypes) {
                foreach ($context in $namingContexts) {
                    $broadFilter = "(&(objectClass=computer)(|(name=$name)(cn=$name)))"
                    $broadObj = Get-ADObject -LDAPFilter $broadFilter -SearchBase $context -SearchScope Subtree -Properties ObjectClass -ErrorAction SilentlyContinue
                    
                    if ($broadObj) {
                        $objectTypes += "Computer"
                        Write-Host "  Found computer with broad search: $($broadObj.Name)" -ForegroundColor Green
                        break
                    }
                }
            }
        }
        
        # Check for Group object
        $adGroup = Get-ADGroup -Filter "Name -eq '$name' -or SamAccountName -eq '$name'" -ErrorAction SilentlyContinue
        if ($adGroup) {
            $objectTypes += "Group"
        }
        
        # Generic object search for other types
        $ldapFilter = "(|(cn=$name)(name=$name)(sAMAccountName=$name))"
        $adObject = Get-ADObject -LDAPFilter $ldapFilter -SearchBase $baseDN -Properties ObjectClass -ErrorAction SilentlyContinue
        
        if ($adObject -and ($adObject.ObjectClass -notin @("user", "computer", "group", "container"))) {
            $objectTypes += $adObject.ObjectClass
        }
        
        # Return results
        if ($objectTypes.Count -gt 0) {
            return ($objectTypes -join ", ")
        } else {
            # One final attempt with a very broad search for computers
            Write-Host "  Object not found with standard methods, trying extended computer search for $name..." -ForegroundColor Yellow
            try {
                # Try with a wildcard search in case it's a prefix of a longer computer name
                $wildcardComputer = Get-ADComputer -Filter {Name -like "$name*"} -ErrorAction SilentlyContinue
                if ($wildcardComputer) {
                    Write-Host "  Found computer with wildcard search: $($wildcardComputer.Name)" -ForegroundColor Green
                    return "Computer (found with wildcard)"
                }
            }
            catch {
                # Suppress wildcard search errors
            }
            
            return "Unknown"
        }
    }
    catch {
        Write-Host "Error identifying object type for $objectName - $($_)" -ForegroundColor Yellow
        return "Error"
    }
}

# Start logging to the log file
Start-Transcript -Path $logFile

# Function to get AD object by name and domain with enhanced name resolution
function Get-ADObjectByName {
    param (
        [string]$objectName,
        [string]$domain
    )
    
    try {
        Write-Host "  Searching for object: '$objectName'" -ForegroundColor Cyan
        
        # Clean the object name first
        $name = Get-CleanObjectName -objectName $objectName
        
        # Build the domain component string for the search base
        $baseDN = ($domain -split '\.') | ForEach-Object { "DC=$_" }
        $baseDN = $baseDN -join ','
        
        # First try direct lookup if it looks like a DN
        if ($objectName -like "*CN=*,*" -or $objectName -like "*OU=*,*") {
            try {
                $adObject = Get-ADObject -Identity $objectName -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
                if ($adObject) {
                    Write-Host "  Found object with direct DN lookup" -ForegroundColor Green
                    return $adObject
                }
            }
            catch {
                # Suppress direct lookup errors
            }
        }
        
        # Try user lookup
        Write-Host "  Checking for user object..." -ForegroundColor Gray
        $adUser = Get-ADUser -Filter "Name -eq '$name' -or SamAccountName -eq '$name'" -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
        if ($adUser) {
            Write-Host "  Found user object: $($adUser.Name)" -ForegroundColor Green
            return $adUser
        }
        
        # Try computer lookup with multiple approaches
        Write-Host "  Checking for computer object..." -ForegroundColor Gray
        try {
            # First attempt: Standard filter with exact name
            $adComputer = Get-ADComputer -Filter {Name -eq $name} -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            if ($adComputer) {
                Write-Host "  Found computer with exact name match: $($adComputer.Name)" -ForegroundColor Green
                return $adComputer
            }
            
            # Second attempt: Try with $ suffix for SAM account name
            $adComputer = Get-ADComputer -Filter {SamAccountName -eq "$name$"} -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            if ($adComputer) {
                Write-Host "  Found computer with SAM account name: $($adComputer.Name)" -ForegroundColor Green
                return $adComputer
            }
            
            # Third attempt: Try DNS hostname matching
            $adComputer = Get-ADComputer -Filter {DNSHostName -like "$name*"} -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            if ($adComputer) {
                Write-Host "  Found computer with DNS hostname match: $($adComputer.Name)" -ForegroundColor Green
                return $adComputer
            }
            
            # Fourth attempt: Direct LDAP query for computers
            Write-Host "  Trying LDAP filter for computer..." -ForegroundColor Gray
            $computerFilter = "(&(objectClass=computer)(|(name=$name)(cn=$name)(dNSHostName=$name*)(sAMAccountName=$name$)))"
            $computerObj = Get-ADObject -LDAPFilter $computerFilter -SearchBase $baseDN -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            if ($computerObj) {
                Write-Host "  Found computer with LDAP filter: $($computerObj.Name)" -ForegroundColor Green
                return $computerObj
            }
            
            # Fifth attempt: Try with just the name in a broader search
            $broadFilter = "(&(objectClass=computer)(|(name=$name)(cn=$name)))"
            $broadObj = Get-ADObject -LDAPFilter $broadFilter -SearchScope Subtree -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            if ($broadObj) {
                Write-Host "  Found computer with broad search: $($broadObj.Name)" -ForegroundColor Green
                return $broadObj
            }
            
            # Sixth attempt: Wildcard search as last resort
            Write-Host "  Trying wildcard search for computers..." -ForegroundColor Gray
            $wildcardComputer = Get-ADComputer -Filter {Name -like "$name*"} -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            if ($wildcardComputer) {
                Write-Host "  Found computer with wildcard search: $($wildcardComputer.Name)" -ForegroundColor Green
                return $wildcardComputer
            }
        }
        catch {
            Write-Host "  Computer lookup failed for $name, trying alternative approaches..." -ForegroundColor Yellow
        }
        
        # Try group lookup
        Write-Host "  Checking for group object..." -ForegroundColor Gray
        $adGroup = Get-ADGroup -Filter "Name -eq '$name' -or SamAccountName -eq '$name'" -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
        if ($adGroup) {
            Write-Host "  Found group object: $($adGroup.Name)" -ForegroundColor Green
            return $adGroup
        }

       
                
        # Try GPO lookup
        Write-Host "  Checking for GPO object..." -ForegroundColor Gray
        $adGPO = Get-ADObject -Filter "DisplayName -eq '$name'" -SearchBase "CN=Policies,CN=System,$baseDN" -properties name,displayname  -ErrorAction SilentlyContinue 
        #$adGroup = Get-ADGroup -Filter "Name -eq '$name' -or SamAccountName -eq '$name'" -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
        if ($adGPO) {
            Write-Host "  Found GPO object: $($adGPO.Name)" -ForegroundColor Green
            return $adGPO
        }
        
        # Try generic object lookup
        Write-Host "  Trying generic object lookup..." -ForegroundColor Gray
        $ldapFilter = "(|(cn=$name)(name=$name)(sAMAccountName=$name))"
        $adObject = Get-ADObject -LDAPFilter $ldapFilter -SearchBase $baseDN -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
        
        if ($adObject) {
            Write-Host "  Found generic object: $($adObject.Name)" -ForegroundColor Green
            return $adObject
        }
        
        # If nothing is found, try searching in all naming contexts
        Write-Host "  Searching in all naming contexts..." -ForegroundColor Gray
        $rootDSE = Get-ADRootDSE
        $namingContexts = @($rootDSE.defaultNamingContext, $rootDSE.configurationNamingContext, $rootDSE.schemaNamingContext)
        
        foreach ($context in $namingContexts) {
            $containerFilter = "(&(objectClass=container)(|(cn=$name)(name=$name)))"
            $containerObject = Get-ADObject -LDAPFilter $containerFilter -SearchBase $context -SearchScope Subtree -Properties objectSid, distinguishedName -ErrorAction SilentlyContinue
            
            if ($containerObject) {
                Write-Host "  Found container object: $($containerObject.Name)" -ForegroundColor Green
                return $containerObject
            }
        }
        
        Write-Host "  Object not found: $objectName" -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "Error finding AD object for $objectName - $($_)" -ForegroundColor Yellow
        return $null
    }
}

# Function to grant GenericAll permission
function Grant-GenericAllPermission {
    param (
        [System.DirectoryServices.DirectoryEntry]$targetObject,
        [System.Security.Principal.SecurityIdentifier]$sourceSid,
        [string]$sourceDisplay
    )
    
    try {
        # Get the ACL for the target object
        $acl = $targetObject.ObjectSecurity
        
        # Create a new access rule for GenericAll permission
        $identity = $sourceSid
        $adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
        $type = [System.Security.AccessControl.AccessControlType]::Allow
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
        $inheritedObjectType = [guid]::Empty
        
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
        
        Write-Host "Successfully granted GenericAll permissions for $sourceDisplay on $($targetObject.distinguishedName)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error granting GenericAll permissions to $sourceDisplay - $($_)" -ForegroundColor Red
        return $false
    }
}

# Process each entry and configure permissions
Write-Host "Processing GenericAll permissions..."
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
        continue
    }
    
    # Get source and target AD objects first
    Write-Host "Searching for source object: $($entry.source)" -ForegroundColor Yellow
    $sourceObject = Get-ADObjectByName -objectName $entry.source -domain $entry.sourceDomain
    
    Write-Host "Searching for target object: $($entry.target)" -ForegroundColor Yellow
    $targetObject = Get-ADObjectByName -objectName $entry.target -domain $entry.sourceDomain
    
    # Determine target object type
    $targetType = "Unknown"
    if ($targetObject) {
        # If we found the object, get its actual class
        if ($targetObject.ObjectClass) {
            $targetType = $targetObject.ObjectClass
        } else {
            # For objects retrieved through Get-ADUser, Get-ADComputer, etc. that don't have ObjectClass property
            $objectDN = $targetObject.DistinguishedName
            $objectWithClass = Get-ADObject -Identity $objectDN -Properties ObjectClass -ErrorAction SilentlyContinue
            if ($objectWithClass) {
                $targetType = $objectWithClass.ObjectClass
            }
        }
        
        # Add container information if applicable
        if ($targetType -eq "container") {
            $context = $targetObject.DistinguishedName -split "," | Where-Object { $_ -like "DC=*" -or $_ -like "CN=Configuration*" } | Select-Object -First 1
            if ($context -like "CN=Configuration*") {
                $targetType = "Container (Configuration)"
            } else {
                $domainPart = ($context -split "=")[1]
                $targetType = "Container ($domainPart)"
            }
        }
    }
    
    # Output information for non-excluded entries
    Write-Host "Source: $($entry.source)"
    Write-Host "Source Domain: $($entry.sourceDomain)"
    Write-Host "Relationship: $($entry.relationship)"
    Write-Host "Target: $($entry.target)"
    Write-Host "Target Type: $targetType"
    
    if ($sourceObject -and $targetObject) {
        Write-Host "Found both source and target objects in AD. Configuring GenericAll permission..." -ForegroundColor Cyan
        
        # Create DirectoryEntry objects for source and target
        $targetDe = [ADSI]"LDAP://$($targetObject.distinguishedName)"
        
        # Grant GenericAll permission
        $result = Grant-GenericAllPermission -targetObject $targetDe -sourceSid $sourceObject.objectSid -sourceDisplay $entry.source
        
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
        }
        if (-not $targetObject) {
            Write-Host "Target object not found in AD: $($entry.target)" -ForegroundColor Yellow
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