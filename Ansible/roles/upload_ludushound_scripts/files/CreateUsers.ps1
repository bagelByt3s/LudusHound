param (
    [Parameter(Mandatory=$true)]
    [string]$f,  # Path to the JSON file

    [Parameter(Mandatory=$false)]
    [int]$c = 0,  # Default to 0, meaning all users will be processed

    [Parameter(Mandatory=$false)]
    [switch]$fullSend  # If specified, create all users
)

# Import the Active Directory module if it's not already loaded
Import-Module ActiveDirectory

# Define the log directory path
$logDirectory = ".\Log\Users"

# Check if the Log directory exists; if not, create it
if (-not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory
}

# Define the log file path with a timestamp
$logPath = ".\Log\Users\Logfile_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start logging to the log file
Start-Transcript -Path $logPath

# Log the start of the script
Write-Host "User creation script started at $(Get-Date)"

# Read and parse the JSON file
$jsonContent = Get-Content -Path $f | Out-String | ConvertFrom-Json

# Flatten the JSON structure if needed (assuming it's an array of arrays)
$users = $jsonContent | ForEach-Object { $_[0] }

# Determine which users to process
if ($fullSend) {
    # If fullSend is specified, process all users
    $usersToProcess = $users
} else {
    # Otherwise, process a limited number based on $c
    if ($c -eq 0) {
        $usersToProcess = $users  # Process all users if $c is 0
    } else {
        $usersToProcess = $users[0..($c - 1)]  # Process only the first $c users
    }
}

# Iterate over the selected users
foreach ($user in $usersToProcess) {
    # Extract necessary user details
    $userName = $user.samaccountname
    $name = $user.name
    $domain = $user.domain
    $description = $user.description
    $enabled = $user.enabled
    $lastLogon = $user.lastlogon
    $displayName = $user.displayname
    $emailAddress = $user.email
    $title = $user.title

    Write-Host "Processing user: $userName"
    Write-Host "Description: $description"

    # Check if the user already exists (optional, you can modify this check)
    $existingUser = Get-ADUser -Filter {SamAccountName -eq $userName} -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Host "User $userName already exists. Skipping creation."
    }
    else {
        # Create the new domain user
        New-ADUser -SamAccountName $userName `
                   -UserPrincipalName "$userName@$domain" `
                   -Name $username `
                   -GivenName $username `
                   -Description $description `
                   -Enabled $enabled `
                   -AccountPassword (ConvertTo-SecureString "password" -AsPlainText -Force) `
                   -PasswordNeverExpires $user.pwdneverexpires `
                   -CannotChangePassword $false `
                   -ChangePasswordAtLogon $false `
                   -PassThru `
                   -DisplayName $displayName `
                   -EmailAddress $emailAddress `
                   -Title $title

        Write-Host "User $userName created successfully."
    }
    
    Write-Host "------------------------------------------------------------------------------"
}

# End the logging
Stop-Transcript

# Log the end of the script
Write-Host "User creation script ended at $(Get-Date)"
