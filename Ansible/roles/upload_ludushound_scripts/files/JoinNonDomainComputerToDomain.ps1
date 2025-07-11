[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$Password
)

# Get current date and time in a filename-friendly format
$dateTime = Get-Date -Format "yyyyMMdd-HHmmss"

# Check if the directory exists and create it if it doesn't
$logDirectory = ".\Log\AddComputerToDomain"
if (-not (Test-Path -Path $logDirectory)) {
    Write-Output "Directory $logDirectory does not exist. Creating it now..."
    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    Write-Output "Directory created successfully."
}

# Start a transcript to log all commands and output with date in filename
Start-Transcript -Path "$logDirectory\domain_join_log_$dateTime.txt" -Append

try {
    # Add timestamp to log entries
    Write-Output "*** Log started at $(Get-Date) ***"
    Write-Output "Starting domain join process"
    Write-Output "Setting domain variables..."
    
    # Format the username correctly if domain isn't included
    if ($Username -notlike "*\*" -and $Username -notlike "*@*") {
        $domainUsername = "$DomainName\$Username"
    } else {
        $domainUsername = $Username
    }
    
    Write-Output "Domain name: $DomainName"
    Write-Output "Username: $domainUsername"
    
    # Convert password to secure string
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($domainUsername, $securePassword)
    
    # Get IP address and domain controller hostname of the domain from the JSON file
    Write-Output "Reading configuration file..."
    $jsonPath = "c:\windows\tasks\ludushound\computerIPConfig.json"
    $serverIP = ""
    $domain = ""
    $dchostname = ""
    
    if (Test-Path -Path $jsonPath) {
        $jsonContent = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        
        # Filter systems to get only the DC for the specified domain
        $domainDC = $jsonContent.systems | Where-Object { 
            $_.domain -eq $DomainName -and $_.ComputerRole -eq "DC" 
        }
        
        if ($domainDC) {
            Write-Output "Found domain controller for $DomainName"
            Write-Output "DC hostname: $($domainDC.hostname)"
            Write-Output "DC IP address: $($domainDC.ipAddr)"
            
            $serverIP = $domainDC.ipAddr
            $domain = $domainDC.domain
            $dchostname = $domainDC.hostname
        } else {
            Write-Output "Error: No domain controller found for $DomainName"
            throw "No domain controller found for $DomainName in configuration file."
        }
    } else {
        Write-Output "Error: Configuration file not found at $jsonPath"
        throw "Configuration file not found at $jsonPath"
    }
    
    $dcFQDN = $dchostname + "." + $domain
    
    # Get current domain information
    $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
    Write-Output "Current domain: $currentDomain"

    # Change DNS to be DC IP
    Write-Output "Setting DNS to DC IP: $serverIP"
    try {
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "$serverIP"
        Write-Output "DNS settings updated successfully."
    } catch {
        Write-Output "Warning: Could not set DNS settings on Ethernet interface. Error: $($_.Exception.Message)"
        Write-Output "Attempting to find primary network adapter..."
        
        # Try to find the primary network adapter
        $primaryAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        if ($primaryAdapter) {
            Write-Output "Found primary adapter: $($primaryAdapter.Name). Attempting to set DNS..."
            Set-DnsClientServerAddress -InterfaceIndex $primaryAdapter.ifIndex -ServerAddresses "$serverIP"
            Write-Output "DNS settings updated on interface $($primaryAdapter.Name)."
        } else {
            Write-Output "Error: Could not find an active network adapter."
            throw "Could not set DNS settings. No active network adapter found."
        }
    }

    # Check if computer already exists in the domain. If it does, delete the object
    $hostname = $env:COMPUTERNAME
    $hostnameWithDollar = $hostname + "$" 
    Write-Output "Checking if $hostname already exists in the domain..."
    
    try {
        $existingComputer = Get-ADComputer -Identity $hostname -Server $serverIP -ErrorAction SilentlyContinue
        
        if ($existingComputer) {
            Write-Output "$hostname already exists in the domain, deleting computer object..."
            Remove-ADComputer -Identity $hostname -Confirm:$false -Server $serverIP -Credential $credential
            Write-Output "Computer object deleted successfully."
        } else {
            Write-Output "No existing computer object found for $hostname."
        }
    } catch {
        Write-Output "Note: Could not check for existing computer object. This may be expected if not yet joined to domain."
        Write-Output "Error details: $($_.Exception.Message)"
    }
    
    # Attempt to join the domain if not already joined
    if ($currentDomain -ne $DomainName) {
        Write-Output "Attempting to join $hostname to $DomainName using DC $dcFQDN..."
        Add-Computer -DomainName $DomainName -Credential $credential -Server $dcFQDN
        Write-Output "Domain join operation completed. A restart may be required."
    } else {
        Write-Output "Computer is already a member of domain $DomainName. No action needed."
    }
    
    Write-Output "*** Log completed at $(Get-Date) ***"
}
catch {
    # Log any errors
    Write-Output "*** Error occurred at $(Get-Date) ***"
    Write-Output "An error occurred:"
    Write-Output $_.Exception.Message
    Write-Output $_.Exception.StackTrace
    exit 1
}
finally {
    # Stop the transcript
    Stop-Transcript
}