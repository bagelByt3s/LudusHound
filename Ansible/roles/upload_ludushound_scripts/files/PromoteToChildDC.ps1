##PromoteToChildDc

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ParentDomain,
    
    [Parameter(Mandatory=$true)]
    [string]$ChildFQDN,
    
    [Parameter(Mandatory=$true)]
    [string]$SafeModeAdministratorPassword,
    
    [Parameter(Mandatory=$false)]
    [string]$EnterpriseAdminAccount = "domainadmin",
    
    [Parameter(Mandatory=$false)]
    [string]$EnterpriseAdminPass = "password"
)

# Define the log directory path
$logDirectory = ".\Log\$ChildFQDN\PromoteToChildDC"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\$ChildFQDN\PromoteToChildDC\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "DNS Config script started at at $(Get-Date)"



# Extract child domain name from the FQDN
$ChildDomainArray = $ChildFQDN.Split('.')
$ChildDomain = $ChildDomainArray[0]

# Validate that the ChildFQDN is properly formed as a subdomain of ParentDomain
$ExpectedParentDomain = $ChildFQDN.Substring($ChildDomain.Length + 1)
if ($ExpectedParentDomain -ne $ParentDomain) {
    Write-Error "Error: The child FQDN $ChildFQDN must be a subdomain of $ParentDomain"
    exit 1
}

# Set up domain admin credentials using the provided parameters
Write-Host "Using enterprise admin credentials for domain promotion"

$Username = "$ParentDomain\$EnterpriseAdminAccount"
$Password = ConvertTo-SecureString $EnterpriseAdminPass -AsPlainText -Force

# Create credential object
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Convert the DSRM password to a secure string
$DSRMPassword = ConvertTo-SecureString $SafeModeAdministratorPassword -AsPlainText -Force

Write-Host "Beginning promotion to child domain controller..."
Write-Host "Parent Domain: $ParentDomain"
Write-Host "Child Domain: $ChildDomain"
Write-Host "Child FQDN: $ChildFQDN"

# Install the required AD DS features if they're not already installed
if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
    Write-Host "Installing AD DS features..."
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}

# Promote the server to a domain controller in a new child domain
try {
    Install-ADDSDomain `
        -Credential $Credential `
        -NewDomainName $ChildDomain `
        -ParentDomainName $ParentDomain `
        -NewDomainNetbiosName $ChildDomain `
        -InstallDNS `
        -CreateDnsDelegation `
        -SafeModeAdministratorPassword $DSRMPassword `
        -Force
    
    Write-Host "Promotion to child domain controller completed successfully." -ForegroundColor Green
    Write-Host "The server will restart automatically to complete the process."
} 
catch {
    Write-Error "Failed to promote to child domain controller: $_"
    exit 1
}


Write-Host "Child DC Promotion Complete" -ForegroundColor Cyan

# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "Promotion script ended at $(Get-Date)"