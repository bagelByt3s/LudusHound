param(
    [string]$f,         # File path
    [int]$c = 0,        # Count of entries to process (0 means all entries)
    [switch]$fullSend,  # Full send flag (process all entries)
    [string]$defaultDomain = ""    # Default domain to use for entries without domain (will be auto-detected if empty)
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

# Auto-detect the current computer's domain if defaultDomain is not provided
if (-not $defaultDomain) {
    try {
        # Try to get the domain from the current computer
        $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
        if (-not $currentDomain) {
            # Fallback to get domain from current user's identity
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            if ($currentUser.Name -like "*\*") {
                $currentDomain = ($currentUser.Name -split "\\")[0]
            }
        }
        
        # If we found a domain, use it
        if ($currentDomain) {
            $defaultDomain = $currentDomain.ToUpper()
            Write-Host "Auto-detected domain: $defaultDomain" -ForegroundColor Green
        } else {
            # If all attempts failed, use the NetBIOS domain name from Active Directory
            Import-Module ActiveDirectory
            $defaultDomain = (Get-ADDomain).NetBIOSName
            Write-Host "Using Active Directory NetBIOS domain: $defaultDomain" -ForegroundColor Green
        }
    } catch {
        # If all auto-detection fails, use a generic placeholder and warn the user
        $defaultDomain = "UNKNOWN"
        Write-Host "WARNING: Could not auto-detect domain. Using placeholder: $defaultDomain. Specify -defaultDomain parameter for your environment." -ForegroundColor Yellow
    }
}

# Create the Log directory if it doesn't exist
$logDir = ".\Log\MembersOf"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"

# Start transcript logging to capture all console output
Start-Transcript -Path "$logDir\Transcript_$dateTime.txt" -Append



### For whatever reason, domain users gets added to remote desktop users group even if json does not specify too. This code checks if domain users is a member of remote desktop users and if it is, removes it before doing all of the domain configurations.


# Get the Remote Desktop Users group from the current domain
$rdpGroup = Get-ADGroup "Remote Desktop Users" -ErrorAction SilentlyContinue
if (-not $rdpGroup) {
    Write-Output "Could not find the 'Remote Desktop Users' group in the current domain."
    exit
}

# Get all members of the Remote Desktop Users group
$rdpMembers = Get-ADGroupMember -Identity $rdpGroup -ErrorAction SilentlyContinue

# Look specifically for any group named "Domain Users" (from any domain)
$domainUsersGroups = $rdpMembers | Where-Object {$_.name -eq "Domain Users"}

if ($domainUsersGroups) {
    Write-Output "Found $(($domainUsersGroups | Measure-Object).Count) 'Domain Users' group(s) in the Remote Desktop Users group."
    
    # Remove each Domain Users group found
    foreach ($domainUsersGroup in $domainUsersGroups) {
        Write-Output "Removing Domain Users group: $($domainUsersGroup.distinguishedName)"
        try {
            Remove-ADGroupMember -Identity $rdpGroup -Members $domainUsersGroup -Confirm:$false -ErrorAction Stop
            Write-Output "Successfully removed $($domainUsersGroup.name) from Remote Desktop Users group."
        } catch {
            Write-Output "Error removing group: $_"
        }
    }
} else {
    Write-Output "No 'Domain Users' groups found in the Remote Desktop Users group. No action needed."
}


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
    $entriesToProcess = $jsonContent[0..($c - 1)]
} else {
    # If neither -fullSend nor a valid -c is provided, process all entries
    $entriesToProcess = $jsonContent
}

# Import the Active Directory module
Import-Module ActiveDirectory

# Function to parse a name that includes domain
function Parse-Name {
    param (
        [string]$NameWithDomain,
        [string]$DefaultDomain
    )
    
    # If the name contains '@', split it to get name and domain
    if ($NameWithDomain -like "*@*") {
        $parts = $NameWithDomain -split '@'
        if ($parts.Count -eq 2) {
            return @{
                Name   = $parts[0].Trim()
                Domain = $parts[1].Trim()
            }
        }
    }
    # If the name doesn't contain '@', use the default domain
    else {
        $infoMessage = "Name '$NameWithDomain' does not include domain, using default domain: $DefaultDomain"
        Write-Host $infoMessage -ForegroundColor Yellow
        Add-Content -Path $logFile -Value $infoMessage
        
        return @{
            Name   = $NameWithDomain.Trim()
            Domain = $DefaultDomain
        }
    }
    
    # If we get here, the format is invalid
    $errorMessage = "Invalid format: $NameWithDomain"
    Write-Host $errorMessage
    Add-Content -Path $logFile -Value $errorMessage
    return $null
}

# Function to get an AD principal object (user, group, or computer)
function Get-ADPrincipalObject {
    param (
        [string]$Name,
        [string]$Domain
    )
    
    # Check for well-known security principals
    $wellKnownSIDs = @{
        "AUTHENTICATED USERS" = "S-1-5-11"
        "EVERYONE" = "S-1-1-0"
        "USERS" = "S-1-5-32-545"
        "PRE-WINDOWS 2000 COMPATIBLE ACCESS" = "S-1-5-32-554"
        "WINDOWS AUTHORIZATION ACCESS GROUP" = "S-1-5-32-560"
        "ENTERPRISE DOMAIN CONTROLLERS" = "S-1-5-9"
        "ADMINISTRATOR" = "S-1-5-21-domain-500"  # Local Administrator account
    }
    
    if ($wellKnownSIDs.ContainsKey($Name)) {
        try {
            # For well-known principals, use the SID to identify them
            # Need to handle the domain SID for Administrator specifically
            $sidString = $wellKnownSIDs[$Name]
            if ($sidString -eq "S-1-5-21-domain-500") {
                # Get the domain SID first
                $domainObj = Get-ADDomain -Server $Domain -ErrorAction Stop
                $domainSID = $domainObj.DomainSID.Value
                $sidString = "$domainSID-500"  # Append the RID for Administrator
            }
            
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidString)
            $ntAccount = $sid.Translate([System.Security.Principal.NTAccount])
            
            # Create a custom object with the necessary properties
            $customPrincipal = [PSCustomObject]@{
                Name = $Name
                SamAccountName = $ntAccount.Value.Split('\')[1]  # Extract account name from domain\account
                DistinguishedName = "CN=$Name,CN=WellKnown Security Principals,DC=BuiltIn"  # Custom DN for well-known principals
                ObjectClass = "wellKnownPrincipal"
                SID = $sid
                IsWellKnown = $true
                NTAccount = $ntAccount.Value  # Store the full NT Account name
            }
            
            $infoMessage = "Identified well-known security principal: $Name with SID: $($sid.Value)"
            Write-Host $infoMessage
            
            return $customPrincipal
        }
        catch {
            $errorMessage = "Error identifying well-known security principal '$Name': $_"
            Write-Host $errorMessage
            return $null
        }
    }
    else {
        # First, determine if it's a computer account by checking the name pattern
        $isComputer = $Name -match "^\w+-?\w+\d+$"  # Simple pattern to match computer names like DENVMKTING934
        
        # Try to find the object as a group, user, or computer
        try {
            if ($isComputer) {
                # Try as a computer first if the name looks like a computer
                $principal = Get-ADComputer -Identity $Name -Server $Domain -ErrorAction Stop
                $objectType = "computer"
                
                $infoMessage = "Successfully found computer account: $Name in domain $Domain"
                Write-Host $infoMessage -ForegroundColor Green
            }
            else {
                # Try as a group first
                $principal = Get-ADGroup -Identity $Name -Server $Domain -ErrorAction Stop
                $objectType = "group"
            }
        }
        catch {
            try {
                if (!$isComputer) {
                    # Try as a user next
                    $principal = Get-ADUser -Identity $Name -Server $Domain -ErrorAction Stop
                    $objectType = "user"
                }
                else {
                    # If we thought it was a computer but couldn't find it, try other types
                    try {
                        $principal = Get-ADGroup -Identity $Name -Server $Domain -ErrorAction Stop
                        $objectType = "group"
                    }
                    catch {
                        try {
                            $principal = Get-ADUser -Identity $Name -Server $Domain -ErrorAction Stop
                            $objectType = "user"
                        }
                        catch {
                            throw $_  # Re-throw the original error
                        }
                    }
                }
            }
            catch {
                try {
                    # Finally, try as a computer if we haven't already
                    if (!$isComputer) {
                        $principal = Get-ADComputer -Identity $Name -Server $Domain -ErrorAction Stop
                        $objectType = "computer"
                    }
                    else {
                        throw $_  # Re-throw the original error if we already tried computer
                    }
                }
                catch {
                    $errorMessage = "Error finding principal '$Name' in domain '$Domain': $_"
                    Write-Host $errorMessage
                    return $null
                }
            }
        }
        
        # Create a custom object to wrap the AD object
        $customPrincipal = [PSCustomObject]@{
            Name = $principal.Name
            SamAccountName = $principal.SamAccountName
            DistinguishedName = $principal.DistinguishedName
            ObjectClass = $objectType
            SID = $principal.SID
            IsWellKnown = $false
            OriginalObject = $principal  # Store original AD object for later use
        }
        
        return $customPrincipal
    }
}

# Function to check if source is already a member of target group
function Test-GroupMembership {
    param (
        [PSObject]$SourcePrincipal,
        [PSObject]$TargetGroup,
        [string]$TargetDomain,
        [bool]$UseCredential = $false,
        [System.Management.Automation.PSCredential]$Credential = $null
    )
    
    # If target is a well-known security principal, we can't check membership directly
    if ($TargetGroup.IsWellKnown) {
        return $false
    }
    
    # If source is a well-known security principal, we need to check membership differently
    if ($SourcePrincipal.IsWellKnown) {
        try {
            # Get all members of the target group
            if ($UseCredential -and $null -ne $Credential) {
                $members = Get-ADGroupMember -Identity $TargetGroup.OriginalObject.DistinguishedName -Server $TargetDomain -Credential $Credential -ErrorAction Stop
            } 
            else {
                $members = Get-ADGroupMember -Identity $TargetGroup.OriginalObject.DistinguishedName -Server $TargetDomain -ErrorAction Stop
            }
            
            # Check SIDs of members against the well-known principal's SID
            foreach ($member in $members) {
                if ($member.SID -eq $SourcePrincipal.SID) {
                    return $true
                }
            }
            
            return $false
        }
        catch {
            $errorMessage = "Error checking group membership for well-known principal: $_"
            Write-Host $errorMessage
            Add-Content -Path $logFile -Value $errorMessage
            
            # If error occurs during membership check, assume not a member to be safe
            return $false
        }
    }
    
    # Regular membership check for standard AD objects
    try {
        # Get all members of the target group
        if ($UseCredential -and $null -ne $Credential) {
            $credMessage = "Using domain admin credentials to check membership in $($TargetGroup.Name)"
            Write-Host $credMessage -ForegroundColor Magenta
            
            $members = Get-ADGroupMember -Identity $TargetGroup.OriginalObject.DistinguishedName -Server $TargetDomain -Credential $Credential -ErrorAction Stop
        } 
        else {
            $members = Get-ADGroupMember -Identity $TargetGroup.OriginalObject.DistinguishedName -Server $TargetDomain -ErrorAction Stop
        }
        
        # Check if source is a member
        foreach ($member in $members) {
            if ($member.SID -eq $SourcePrincipal.SID) {
                return $true
            }
        }
        
        return $false
    }
    catch {
        $errorMessage = "Error checking group membership: $_"
        Write-Host $errorMessage
        
        # If error occurs during membership check, assume not a member to be safe
        return $false
    }
}

# Start processing
$totalEntries = $entriesToProcess.Count
$processedCount = 0

Write-Host "Starting to process $totalEntries entries. Transcript log: $logDir\Transcript_$dateTime.txt"
Write-Host "Processing started at $(Get-Date)"

# Process each relationship
foreach ($relationship in $entriesToProcess) {
    $processedCount++
    $statusMessage = "Processing $processedCount of $totalEntries - Source: $($relationship.source) -> Target: $($relationship.target)"
    Write-Host $statusMessage
    
    # Skip if not a MemberOf relationship
    if ($relationship.relationship -ne "MemberOf") {
        $skipMessage = "Skipping: Not a MemberOf relationship"
        Write-Host $skipMessage
        Add-Content -Path $logFile -Value $skipMessage
        continue
    }
    
    # Parse source and target names, using default domain if needed
    $sourcePrincipal = Parse-Name -NameWithDomain $relationship.source -DefaultDomain $defaultDomain
    $targetGroup = Parse-Name -NameWithDomain $relationship.target -DefaultDomain $defaultDomain
    
    if ($null -eq $sourcePrincipal -or $null -eq $targetGroup) {
        $skipMessage = "Skipping: Invalid format"
        Write-Host $skipMessage
        Add-Content -Path $logFile -Value $skipMessage
        continue
    }
    
    # Get AD objects
    $sourceADPrincipal = Get-ADPrincipalObject -Name $sourcePrincipal.Name -Domain $sourcePrincipal.Domain
    $targetADGroup = Get-ADPrincipalObject -Name $targetGroup.Name -Domain $targetGroup.Domain
    
    if ($null -eq $sourceADPrincipal -or $null -eq $targetADGroup) {
        $skipMessage = "Skipping: Could not find one or both objects"
        Write-Host $skipMessage
        Add-Content -Path $logFile -Value $skipMessage
        continue
    }
    
    # Verify target is actually a group (or a well-known principal that can have members)
    if (-not $targetADGroup.IsWellKnown -and $targetADGroup.ObjectClass -ne "group") {
        $errorMessage = "Error: Target '$($targetGroup.Name)' is not a group but a $($targetADGroup.ObjectClass)"
        Write-Host $errorMessage -ForegroundColor Red
        Add-Content -Path $logFile -Value $errorMessage
        continue
    }
    
    # Process the relationship
    try {
        # Handle the case where one or both are well-known security principals
        if ($sourceADPrincipal.IsWellKnown -or $targetADGroup.IsWellKnown) {
            # Handle well-known security principals based on different scenarios
            
            # Scenario 1: Both source and target are well-known security principals
            if ($sourceADPrincipal.IsWellKnown -and $targetADGroup.IsWellKnown) {
                $infoMessage = "INFO: Both source and target are well-known security principals. This relationship can't be directly established."
                Write-Host $infoMessage -ForegroundColor Cyan
                Add-Content -Path $logFile -Value $infoMessage
                continue
            }
            
            # Scenario 2: Source is a well-known security principal, target is a regular group
            if ($sourceADPrincipal.IsWellKnown -and -not $targetADGroup.IsWellKnown) {
                # Check if cross-domain operation
                $crossDomain = $sourcePrincipal.Domain -ne $targetGroup.Domain
                
                if ($crossDomain) {
                    # Create credential for the target domain
                    $securePassword = ConvertTo-SecureString "password" -AsPlainText -Force
                    $domainAdminCred = New-Object System.Management.Automation.PSCredential ("$($targetGroup.Domain)\domainadmin", $securePassword)
                    
                    # Check membership
                    $isMember = Test-GroupMembership -SourcePrincipal $sourceADPrincipal -TargetGroup $targetADGroup -TargetDomain $targetGroup.Domain -UseCredential $true -Credential $domainAdminCred
                } else {
                    $isMember = Test-GroupMembership -SourcePrincipal $sourceADPrincipal -TargetGroup $targetADGroup -TargetDomain $targetGroup.Domain
                }
                
                if ($isMember) {
                    $alreadyMessage = "INFO: Well-known principal '$($sourcePrincipal.Name)' is already a member of '$($targetGroup.Name)' - Skipping"
                    Write-Host $alreadyMessage -ForegroundColor Yellow
                    Add-Content -Path $logFile -Value $alreadyMessage
                    continue
                }
                
                # Add the well-known security principal to the regular group
                $ntAccountName = $sourceADPrincipal.NTAccount
                
                if ($crossDomain) {
                    # Create credential for the target domain
                    $securePassword = ConvertTo-SecureString "password" -AsPlainText -Force
                    $domainAdminCred = New-Object System.Management.Automation.PSCredential ("$($targetGroup.Domain)\domainadmin", $securePassword)
                    
                    $credMessage = "Using domain admin credentials for cross-domain operation to $($targetGroup.Domain)"
                    Write-Host $credMessage -ForegroundColor Magenta
                    Add-Content -Path $logFile -Value $credMessage
                    
                    # Use the NTAccount name to add the well-known principal to the group
                    Add-ADGroupMember -Identity $targetADGroup.OriginalObject -Members $ntAccountName -Server $targetGroup.Domain -Credential $domainAdminCred -ErrorAction Stop
                } else {
                    # Use the NTAccount name to add the well-known principal to the group
                    Add-ADGroupMember -Identity $targetADGroup.OriginalObject -Members $ntAccountName -Server $targetGroup.Domain -ErrorAction Stop
                }
                
                $successMessage = "Success: Added well-known principal '$($sourcePrincipal.Name)' to '$($targetGroup.Name)'"
                Write-Host $successMessage -ForegroundColor Green
                Add-Content -Path $logFile -Value $successMessage
                continue
            }
            
            # Scenario 3: Target is a well-known security principal
            if (-not $sourceADPrincipal.IsWellKnown -and $targetADGroup.IsWellKnown) {
                $infoMessage = "INFO: Target '$($targetGroup.Name)' is a well-known security principal. Membership can't be directly modified for well-known groups."
                Write-Host $infoMessage -ForegroundColor Cyan
                Add-Content -Path $logFile -Value $infoMessage
                continue
            }
        }
        else {
            # Regular AD objects (non well-known)
            
            # Check if this is a cross-domain operation
            $crossDomain = $sourcePrincipal.Domain -ne $targetGroup.Domain
            
            # Check if source is already a member of target
            if ($crossDomain) {
                # Create credential for the target domain
                $securePassword = ConvertTo-SecureString "password" -AsPlainText -Force
                $domainAdminCred = New-Object System.Management.Automation.PSCredential ("$($targetGroup.Domain)\domainadmin", $securePassword)
                
                # Use credentials for membership check if cross-domain
                $isMember = Test-GroupMembership -SourcePrincipal $sourceADPrincipal -TargetGroup $targetADGroup -TargetDomain $targetGroup.Domain -UseCredential $true -Credential $domainAdminCred
            }
            else {
                $isMember = Test-GroupMembership -SourcePrincipal $sourceADPrincipal -TargetGroup $targetADGroup -TargetDomain $targetGroup.Domain
            }
            
            if ($isMember) {
                $alreadyMessage = "INFO: '$($sourcePrincipal.Name)' ($($sourceADPrincipal.ObjectClass)) is already a member of '$($targetGroup.Name)' - Skipping"
                Write-Host $alreadyMessage -ForegroundColor Yellow
                Add-Content -Path $logFile -Value $alreadyMessage
            }
            else {
                if ($crossDomain) {
                    # Create credential for the target domain
                    $securePassword = ConvertTo-SecureString "password" -AsPlainText -Force
                    $domainAdminCred = New-Object System.Management.Automation.PSCredential ("$($targetGroup.Domain)\domainadmin", $securePassword)
                    
                    $credMessage = "Using domain admin credentials for cross-domain operation to $($targetGroup.Domain)"
                    Write-Host $credMessage -ForegroundColor Magenta
                    Add-Content -Path $logFile -Value $credMessage
                    
                    # For regular AD groups, use Add-ADGroupMember with credentials
                    Add-ADGroupMember -Identity $targetADGroup.OriginalObject -Members $sourceADPrincipal.OriginalObject -Server $targetGroup.Domain -Credential $domainAdminCred -ErrorAction Stop
                    $successMessage = "Success: Added '$($sourcePrincipal.Name)' ($($sourceADPrincipal.ObjectClass)) to '$($targetGroup.Name)' using domain admin credentials"
                    Write-Host $successMessage -ForegroundColor Green
                    Add-Content -Path $logFile -Value $successMessage
                }
                else {
                    # For regular AD groups, use Add-ADGroupMember
                    Add-ADGroupMember -Identity $targetADGroup.OriginalObject -Members $sourceADPrincipal.OriginalObject -Server $targetGroup.Domain -ErrorAction Stop
                    $successMessage = "Success: Added '$($sourcePrincipal.Name)' ($($sourceADPrincipal.ObjectClass)) to '$($targetGroup.Name)'"
                    Write-Host $successMessage -ForegroundColor Green
                    Add-Content -Path $logFile -Value $successMessage
                }
            }
        }
    }
    catch {
        $errorMessage = "Error: Failed to add '$($sourcePrincipal.Name)' to '$($targetGroup.Name)': $_"
        Write-Host $errorMessage -ForegroundColor Red
        Add-Content -Path $logFile -Value $errorMessage
    }
}

$completionMessage = "Processing complete. Processed $processedCount of $totalEntries entries."
Write-Host $completionMessage
Add-Content -Path $logFile -Value $completionMessage
Add-Content -Path $logFile -Value "Processing completed at $(Get-Date)"

# Stop transcript logging
Stop-Transcript