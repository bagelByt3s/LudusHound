# Detect FQDN and NetBIOS domain names
$computerSystem = Get-WmiObject Win32_ComputerSystem
$fqdnDomain = $computerSystem.Domain

# Get the NetBIOS domain name
$netbiosDomain = (Get-WmiObject Win32_NTDomain | Where-Object { $_.DnsForestName -eq $fqdnDomain }).DomainName

# Local group
$groupName = "Remote Desktop Users"

# Domain group formats
$domainUsersFqdn = "$fqdnDomain\Domain Users"
$domainUsersNetbios = "$netbiosDomain\Domain Users"
$domainAdminsNetbios = "$netbiosDomain\Domain Admins"

# Remove Domain Users (FQDN and NetBIOS formats)
$groupMembers = net localgroup "$groupName"

if ($groupMembers -match [regex]::Escape($domainUsersFqdn)) {
    Write-Output "Removing '$domainUsersFqdn' from '$groupName'..."
    cmd /c "net localgroup `"$groupName`" `"$domainUsersFqdn`" /delete"
} else {
    Write-Output "'$domainUsersFqdn' is not a member of '$groupName'."
}

if ($groupMembers -match [regex]::Escape($domainUsersNetbios)) {
    Write-Output "Removing '$domainUsersNetbios' from '$groupName'..."
    cmd /c "net localgroup `"$groupName`" `"$domainUsersNetbios`" /delete"
} else {
    Write-Output "'$domainUsersNetbios' is not a member of '$groupName'."
}

# Add Domain Admins (NetBIOS format only)
if ($groupMembers -notmatch [regex]::Escape($domainAdminsNetbios)) {
    Write-Output "Adding '$domainAdminsNetbios' to '$groupName'..."
    cmd /c "net localgroup `"$groupName`" `"$domainAdminsNetbios`" /add"
} else {
    Write-Output "'$domainAdminsNetbios' is already a member of '$groupName'."
}
