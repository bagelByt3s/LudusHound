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
$logDir = ".\Log\DCSync"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force
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
    $jsonContent = $jsonContent
} elseif ($c -gt 0) {
    # If -c is provided and greater than 0, process the first $c entries
    $jsonContent = $jsonContent[0..($c - 1)]  # Get the first $c entries
}

function Check-DCSyncPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Account,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$false)]
        [string]$SourceDomain = $null
    )
    
    begin {
        # Import the Active Directory module if not already loaded
        if (-not (Get-Module -Name ActiveDirectory)) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Verbose "Successfully imported ActiveDirectory module"
            }
            catch {
                Write-Error "Failed to import ActiveDirectory module. Please ensure it is installed."
                return $false
            }
        }
    }
    
    process {
        try {
            # Get the Root DSE for the target domain
            try {
                $rootDSE = Get-ADRootDSE -Server $Domain
            } catch {
                Write-Error "Failed to connect to domain $Domain - $_"
                return
            }
            
            # Define the DCSync permission GUIDs
            $replicatingChangesGUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
            $replicatingChangesAllGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
            $dcsyncGUIDs = @($replicatingChangesGUID, $replicatingChangesAllGUID)
            
            # Get domain ACL - need to use proper AD path for cross-domain
            $domainDN = $rootDSE.defaultNamingContext
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
            try {
                $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
                $dc = $domainObj.DomainControllers[0].Name
                $adPath = "LDAP://$dc/$domainDN"
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($adPath)
                $acl = $directoryEntry.ObjectSecurity
            } catch {
                Write-Error "Failed to connect to domain $Domain - $_"
                return $false
            }
            
            # Determine if this is a user or computer account
            $accountType = "Unknown"
            $accountExistance = $false
            $adAccount = $null
            
            # Determine which domain to search for the account
            $searchDomain = if ($SourceDomain) { $SourceDomain } else { $Domain }
            Write-Verbose "Searching for account in domain: $searchDomain"
            
            # Try as user account
            try {
                $adAccount = Get-ADUser -Identity $Account -Server $searchDomain -ErrorAction Stop
                $accountType = "User"
                $accountExistance = $true
                Write-Verbose "$Account found as a user account in $searchDomain"
            }
            catch {
                # Try as computer account
                try {
                    $adAccount = Get-ADComputer -Identity $Account -Server $searchDomain -ErrorAction Stop
                    $accountType = "Computer"
                    $accountExistance = $true
                    Write-Verbose "$Account found as a computer account in $searchDomain"
                }
                catch {
                    # Try user by UPN
                    try {
                        $adAccount = Get-ADUser -Filter "UserPrincipalName -eq '$Account@$searchDomain'" -Server $searchDomain -ErrorAction Stop
                        $accountType = "User"
                        $accountExistance = $true
                        Write-Verbose "$Account found as a user account via UPN in $searchDomain"
                    }
                    catch {
                        # Try computer with FQDN
                        try {
                            $adAccount = Get-ADComputer -Filter "DNSHostName -eq '$Account.$searchDomain'" -Server $searchDomain -ErrorAction Stop
                            $accountType = "Computer"
                            $accountExistance = $true
                            Write-Verbose "$Account found as a computer account via FQDN in $searchDomain"
                        }
                        catch {
                            Write-Warning "Could not find $Account in Active Directory ($searchDomain) as either a user or computer account."
                            # Continue and rely on string matching since SID matching is not possible
                        }
                    }
                }
            }
            
            # Prepare search strings for the account - handle various formats
            $searchStrings = @(
                "$searchDomain\$Account",      # DOMAIN\account format
                "$Account@$searchDomain",      # account@domain.com format
                "$Account"                     # Just account name
            )
            
            # Add computer account specific search strings with $ suffix if this is a computer
            if ($accountType -eq "Computer") {
                $searchStrings += @(
                    "$searchDomain\$Account$",  # DOMAIN\account$ format
                    "$Account$"                 # account$ format (computers have $ appended in AD)
                )
            }
            
            # If we found the account, add its SID to the search criteria
            if ($accountExistance -and $adAccount) {
                $sid = $adAccount.SID.Value
                Write-Verbose "Found $accountType $Account with SID: $sid"
            }
            
            # Filter and display account's DCSync permissions
            $dcsyncPermissions = $acl.Access | Where-Object { 
                (($searchStrings -contains $_.IdentityReference.ToString()) -or 
                 ($_.IdentityReference.ToString() -like "*\$Account") -or 
                 ($_.IdentityReference.ToString() -like "*\$Account$") -or 
                 ($_.IdentityReference.ToString() -like "$Account@*") -or
                 ($accountExistance -and $adAccount -and $_.IdentityReference.ToString() -eq $sid)) -and 
                ($dcsyncGUIDs -contains $_.ObjectType.ToString())
            }
            
            # Display results
            if ($dcsyncPermissions) {
                $count = ($dcsyncPermissions | Measure-Object).Count
                $typeText = if ($accountType -ne "Unknown") { $accountType } else { "Account" }
                Write-Host "$typeText '$Account' has $count DCSync permission(s) in the $Domain domain:" -ForegroundColor Green
                $dcsyncPermissions | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType, ObjectType -AutoSize
                return $true
            } else {
                $typeText = if ($accountType -ne "Unknown") { $accountType } else { "Account" }
                Write-Host "$typeText '$Account' does not have any DCSync permissions in the $Domain domain." -ForegroundColor Red
                return $false
            }
        }
        catch {
            Write-Error "An error occurred while checking DCSync permissions: $_"
            return $false
        }
    }
}

function Grant-DCSyncPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Account,
        
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$false)]
        [string]$SourceDomain = $null
    )
    
    begin {
        # Import the Active Directory module if not already loaded
        if (-not (Get-Module -Name ActiveDirectory)) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Verbose "Successfully imported ActiveDirectory module"
            }
            catch {
                Write-Error "Failed to import ActiveDirectory module. Please ensure it is installed."
                return
            }
        }
    }
    
    process {
        try {
            # Get the Root DSE for the target domain
            try {
                $rootDSE = Get-ADRootDSE -Server $Domain
            } catch {
                Write-Error "Failed to connect to domain $Domain - $_"
                return $false
            }
            
            # Define the extended rights GUIDs for DCSync
            $replicatingChangesGUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
            $replicatingChangesAllGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
            
            # Get the current ACL for the domain - use DirectoryEntry for cross-domain access
            $domainDN = $rootDSE.defaultNamingContext
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
            try {
                $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
                $dc = $domainObj.DomainControllers[0].Name
                $adPath = "LDAP://$dc/$domainDN"
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($adPath)
                $acl = $directoryEntry.ObjectSecurity
            } catch {
                Write-Error "Failed to connect to domain $Domain - $_"
                return
            }
            
            # Determine if this is a user or computer account
            $accountType = "Unknown"
            $adAccount = $null
            
            # Determine which domain to search for the account
            $searchDomain = if ($SourceDomain) { $SourceDomain } else { $Domain }
            Write-Verbose "Searching for account in domain: $searchDomain"
            
            # Try as user account
            try {
                $adAccount = Get-ADUser -Identity $Account -Server $searchDomain -ErrorAction Stop
                $accountType = "User"
                Write-Verbose "$Account found as a user account in $searchDomain"
            }
            catch {
                # Try as computer account
                try {
                    $adAccount = Get-ADComputer -Identity $Account -Server $searchDomain -ErrorAction Stop
                    $accountType = "Computer"
                    Write-Verbose "$Account found as a computer account in $searchDomain"
                }
                catch {
                    # Try user by UPN
                    try {
                        $adAccount = Get-ADUser -Filter "UserPrincipalName -eq '$Account@$searchDomain'" -Server $searchDomain -ErrorAction Stop
                        $accountType = "User"
                        Write-Verbose "$Account found as a user account via UPN in $searchDomain"
                    }
                    catch {
                        # Try computer with FQDN
                        try {
                            $adAccount = Get-ADComputer -Filter "DNSHostName -eq '$Account.$searchDomain'" -Server $searchDomain -ErrorAction Stop
                            $accountType = "Computer"
                            Write-Verbose "$Account found as a computer account via FQDN in $searchDomain"
                        }
                        catch {
                            Write-Error "Could not find $Account in $searchDomain Active Directory as either a user or computer account. Please check the name and try again."
                            return
                        }
                    }
                }
            }
            
            if ($adAccount -eq $null) {
                Write-Error "Failed to retrieve AD account object for $Account in domain $searchDomain"
                return
            }
            
            $sid = $adAccount.SID
            Write-Verbose "Found SID for $accountType $Account in $searchDomain - $sid"
            
            # Create ACEs for both required permissions 
            $objectGuid1 = New-Object Guid $replicatingChangesGUID
            $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AccessControlType]::Allow, $objectGuid1)
            
            $objectGuid2 = New-Object Guid $replicatingChangesAllGUID
            $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AccessControlType]::Allow, $objectGuid2)
            
            # Add the ACEs to the ACL
            $acl.AddAccessRule($ace1)
            $acl.AddAccessRule($ace2)
            
            # Apply the updated ACL back to the domain
            try {
                # Apply the ACL back to the directory entry
                $directoryEntry.CommitChanges()
                Write-Verbose "Changes committed to directory"
                Write-Host "Successfully granted DCSync permissions to $accountType '$Account' from domain $searchDomain in target domain $Domain" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to set ACL. You may not have sufficient permissions: $_"
            }
        }
        catch {
            Write-Error "An error occurred while granting DCSync permissions: $_"
        }
    }
    
    end {
        # Verify the permissions were set
        try {
            if (Get-Command "Check-DCSyncPermissions" -ErrorAction SilentlyContinue) {
                Write-Verbose "Verifying permissions using Check-DCSyncPermissions function"
                Check-DCSyncPermissions -Account $Account -Domain $Domain -SourceDomain $SourceDomain
            }
            else {
                # Fallback verification if Check-DCSyncPermissions isn't available
                Write-Verbose "Check-DCSyncPermissions function not found. Performing basic verification..."
                $domainDN = $rootDSE.defaultNamingContext
                $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
                try {
                    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
                    $dc = $domainObj.DomainControllers[0].Name
                    $adPath = "LDAP://$dc/$domainDN"
                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($adPath)
                    $acl = $directoryEntry.ObjectSecurity
                } catch {
                    Write-Warning "Failed to connect to domain $Domain for verification - $_"
                    return
                }
                $dcsyncGUIDs = @($replicatingChangesGUID, $replicatingChangesAllGUID)
                
                # Prepare search strings for the account
                $searchStrings = @(
                    "$searchDomain\$Account",
                    "$Account@$searchDomain",
                    "$Account"
                )
                
                $hasPermissions = $false
                foreach ($entry in $acl.Access) {
                    if (($searchStrings -contains $entry.IdentityReference.ToString() -or 
                         $entry.IdentityReference.ToString() -like "*\$Account" -or 
                         $entry.IdentityReference.ToString() -like "$Account@*" -or
                         $entry.IdentityReference.ToString() -eq $sid.Value) -and 
                        ($dcsyncGUIDs -contains $entry.ObjectType.ToString())) {
                        $hasPermissions = $true
                        break
                    }
                }
                
                if ($hasPermissions) {
                    Write-Host "Verification successful - DCSync permissions are set for $accountType '$Account'" -ForegroundColor Green
                }
                else {
                    Write-Warning "Verification failed - Could not find DCSync permissions for $accountType '$Account'"
                }
            }
        }
        catch {
            Write-Warning "Failed to verify permissions: $_"
        }
        
        Write-Verbose "Completed Grant-DCSyncPermissions function"
    }
}

# Start logging to the log file
Start-Transcript -Path $logFile

# Iterate through each object in the JSON array, log source and target
foreach ($entry in $jsonContent) {
    $source = $($entry.source)
    
    # Fixed parsing logic for source name extraction
    if ($source -like "*@*") {
        # Format: john.smith@ghost.local or john@ghost.local
        $sourceShortName = $source.Split('@')[0]
        Write-Host "Found @ format, extracted: $sourceShortName"
    } elseif ($source -like "*.*" -and $source.Split('.').Count -gt 2) {
        # Format: john.smith.ghost.local (FQDN format with multiple dots)
        # Take everything before the last two parts (assuming domain.tld)
        $parts = $source.Split('.')
        if ($parts.Count -ge 3) {
            # Join all parts except the last two (domain.tld)
            $sourceShortName = ($parts[0..($parts.Count - 3)] -join '.')
        } else {
            # Fallback: just take the first part
            $sourceShortName = $parts[0]
        }
        Write-Host "Found FQDN format, extracted: $sourceShortName"
    } else {
        # Simple format: just the name without domain info
        $sourceShortName = $source
        Write-Host "Simple format, using as-is: $sourceShortName"
    }
    
    $sourceDomain = $($entry.sourceDomain)
    $target = $($entry.target)
    
    if (-not ($sourceShortName -eq "Administrators")) {
        echo "Source: $source Target: $target"
        echo "Checking if $source is a domain admin"

        try {
            # Try to check if the user is a domain admin in their source domain
            if (-not (Get-ADGroupMember -Identity "Domain Admins" -Server $sourceDomain -Recursive | 
                      Where-Object {$_.SamAccountName -eq $sourceShortName})) {
                Write-Host "$sourceShortName is not a Domain Admin in $sourceDomain. Continuing..."
                echo "Checking if $source is a member of Administrators group"

                if (-not (Get-ADGroupMember -Identity "Administrators" -Server $sourceDomain -Recursive |         
                          Where-Object {$_.objectClass -eq "group" -and 
                                       ($_.Name -eq $source -or $_.SamAccountName -eq $source -or $_.DistinguishedName -eq $source)})) {
                    Write-Host "$source is not a member of Administrators in $sourceDomain. Continuing..."
               
                    # Check if source is a domain controller
                    echo "Checking if $source is a Domain Controller"
                    if (-not (Get-ADDomainController -Filter {Name -eq $sourceShortName} -Server $sourceDomain -ErrorAction SilentlyContinue)) {
                        Write-Host "$source is not a domain controller in $sourceDomain. Continuing..."
                    
                        echo "Configuring $source with DCSync Permissions"
                        # Pass the source domain to the Grant-DCSyncPermissions function
                        Grant-DCSyncPermissions -Account $sourceShortName -Domain $target -SourceDomain $sourceDomain
                    } else {
                        Write-Host "$source is a domain controller in $sourceDomain. Skipping..."
                    }
                } else {
                    Write-Host "$source is a member of Administrators in $sourceDomain. Stopping..."       
                }
            } else {
                Write-Host "$sourceShortName is a Domain Admin in $sourceDomain. Stopping..."
            }
        }
        catch {
            Write-Warning "Error checking permissions in domain $sourceDomain for $source - $_"
            # If the check fails because of domain connectivity issues, we can still try to set the permissions
            echo "Proceeding with configuring $source with DCSync Permissions despite domain check errors"
            Grant-DCSyncPermissions -Account $sourceShortName -Domain $target -SourceDomain $sourceDomain
        }
    }
}

# End the logging
Stop-Transcript

# Inform the user about the log file location
Write-Host "Log file created at: $logFile"