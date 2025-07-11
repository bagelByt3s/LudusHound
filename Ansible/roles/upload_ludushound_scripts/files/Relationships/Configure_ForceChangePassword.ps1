param(
    [string]$f,         # File path
    [int]$c = 0,        # Count of entries to process (0 means all entries)
    [switch]$fullSend,  # Full send flag (process all entries)
    [string]$defaultDomain = "COVERTIUS.LOCAL"  # Default domain to use for entries without domain
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
$logDir = ".\Log\ForceChangePassword"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Get the current date and time for the log file
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$logDir\LogFile_$dateTime.txt"
Start-Transcript -Path $logFile

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

# Start processing
$totalEntries = $entriesToProcess.Count
$processedCount = 0

Write-Host "Starting to process $totalEntries entries. Log file: $logFile"

# Process each relationship
foreach ($relationship in $entriesToProcess) {
    $processedCount++
    
    # Skip if not a ForceChangePassword relationship
    if ($relationship.relationship -ne "ForceChangePassword") {
        Write-Host "Skipping: Not a ForceChangePassword relationship" -ForegroundColor Yellow
        continue
    }
    
    # Get source and target information
    $sourceDN = if ($relationship.PSObject.Properties.Name -contains "sourceDN") { $relationship.sourceDN } else { $relationship.source }
    $targetDN = if ($relationship.PSObject.Properties.Name -contains "targetDN") { $relationship.targetDN } else { $relationship.target }
    
    # Extract domain information
    $sourceDomain = $defaultDomain
    if ($relationship.PSObject.Properties.Name -contains "sourceDomain") { 
        $sourceDomain = $relationship.sourceDomain 
    } elseif ($sourceDN -match '@(.+)$') { 
        $sourceDomain = $matches[1]
    }
    
    $targetDomain = $defaultDomain
    if ($relationship.PSObject.Properties.Name -contains "targetDomain") { 
        $targetDomain = $relationship.targetDomain 
    } elseif ($targetDN -match '@(.+)$') { 
        $targetDomain = $matches[1]
    }
    
    Write-Host "Processing $processedCount of $totalEntries - Source: $sourceDN -> Target: $targetDN" -ForegroundColor Cyan
    
    try {
        # Extract username parts without domain if email format is used
        $sourceUser = $sourceDN
        if ($sourceDN -match '^(.+)@') { 
            $sourceUser = $matches[1]
        }
        
        $targetUser = $targetDN
        if ($targetDN -match '^(.+)@') { 
            $targetUser = $matches[1]
        }
        
        # Get the user objects
        $sourceUserObj = Get-ADUser -Identity $sourceUser -Server $sourceDomain -ErrorAction Stop
        $targetUserObj = Get-ADUser -Identity $targetUser -Server $targetDomain -ErrorAction Stop
        
        # Check if this is a cross-domain operation
        $crossDomain = $sourceDomain -ne $targetDomain
        
        if ($crossDomain) {
            Write-Host "Cross-domain operation detected: $sourceDomain -> $targetDomain" -ForegroundColor Magenta
            
            # Create credentials for the target domain
            $securePassword = ConvertTo-SecureString "password" -AsPlainText -Force
            $domainAdminCred = New-Object System.Management.Automation.PSCredential ("$targetDomain\domainadmin", $securePassword)
            
            # Create DirectoryEntry with explicit credentials
            $ldapPath = "LDAP://$targetDomain/$($targetUserObj.DistinguishedName)"
            $dirEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $domainAdminCred.UserName, $domainAdminCred.GetNetworkCredential().Password)
            
            # Get the security descriptor
            $acl = $dirEntry.ObjectSecurity
            
            # Check if the permission already exists
            $forceChangePwdGUID = [Guid] "00299570-246d-11d0-a768-00aa006e0529"
            $permissionExists = $false
            
            # Convert the source user's SID to NTAccount format for the ACE
            $sourceUserNTAccount = $sourceUserObj.SID.Translate([System.Security.Principal.NTAccount]).Value
            
            # Check the access rules
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
                if (($ace.ObjectType -eq $forceChangePwdGUID) -and 
                    ($ace.ActiveDirectoryRights -match "ExtendedRight") -and 
                    ($ace.IdentityReference.Value -eq $sourceUserNTAccount)) {
                    $permissionExists = $true
                    break
                }
            }
            
            if ($permissionExists) {
                Write-Host "INFO: '$($sourceUserObj.SamAccountName)' already has ForceChangePassword permission on '$($targetUserObj.SamAccountName)' - Skipping" -ForegroundColor Yellow
                continue
            }
            
            # Create a new access rule for the source user
            $identity = $sourceUserObj.SID
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
            
            # Create and add the access rule
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $identity, $adRights, $type, $forceChangePwdGUID, $inheritanceType
            
            $acl.AddAccessRule($accessRule)
            
            # Save the changes back to the directory
            $dirEntry.CommitChanges()
            $dirEntry.Close()
            
            Write-Host "Success: Granted ForceChangePassword permission from '$($sourceUserObj.SamAccountName)' to '$($targetUserObj.SamAccountName)' (cross-domain)" -ForegroundColor Green
        }
        else {
            # Standard within-domain handling
            # Get the current ACL of the target user
            $acl = Get-Acl -Path "AD:$($targetUserObj.DistinguishedName)" -ErrorAction Stop
            
            # Check if the permission already exists
            $forceChangePwdGUID = [Guid] "00299570-246d-11d0-a768-00aa006e0529"
            $permissionExists = $false
            
            foreach ($ace in $acl.Access) {
                if (($ace.ObjectType -eq $forceChangePwdGUID.ToString()) -and 
                    ($ace.ActiveDirectoryRights -match "ExtendedRight") -and 
                    ($ace.IdentityReference.Value -eq $sourceUserObj.SID.Translate([System.Security.Principal.NTAccount]).Value)) {
                    $permissionExists = $true
                    break
                }
            }
            
            if ($permissionExists) {
                Write-Host "INFO: '$($sourceUserObj.SamAccountName)' already has ForceChangePassword permission on '$($targetUserObj.SamAccountName)' - Skipping" -ForegroundColor Yellow
                continue
            }
            
            # Create a new access control entry (ACE)
            $identity = [System.Security.Principal.IdentityReference] $sourceUserObj.SID
            $adRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
            $type = [System.Security.AccessControl.AccessControlType] "Allow"
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
            
            # Create the ACE and add it to the ACL
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $forceChangePwdGUID, $inheritanceType
            $acl.AddAccessRule($ace)
            
            # Apply the modified ACL back to the target user
            Set-Acl -Path "AD:$($targetUserObj.DistinguishedName)" -AclObject $acl -ErrorAction Stop
            
            Write-Host "Success: Granted ForceChangePassword permission from '$($sourceUserObj.SamAccountName)' to '$($targetUserObj.SamAccountName)'" -ForegroundColor Green
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Host "Error processing $sourceDN -> $targetDN : $errorMsg" -ForegroundColor Red
    }
}

$completionMessage = "Processing complete. Processed $processedCount of $totalEntries entries."
Write-Host $completionMessage

# End the logging
Stop-Transcript