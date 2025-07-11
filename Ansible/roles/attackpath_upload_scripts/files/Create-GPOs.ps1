# Create GPOs Script
# Save as: Create-GPOs.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [PSCustomObject]$Node
)

function New-GPOFromNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Node
    )
    
    try {
        $gpoName = $Node.label -replace '@.*$'
        
        $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if (-not $existingGPO) {
            $gpo = New-GPO -Name $gpoName -Comment "Created by Attack Path script"
            Write-Host "Created GPO: $gpoName" -ForegroundColor Green
        }
        else {
            Write-Host "GPO already exists: $gpoName" -ForegroundColor Yellow
            $gpo = $existingGPO
        }
        
        return $gpo
    }
    catch {
        Write-Error "Failed to create GPO '$($Node.label)': $_"
        return $null
    }
}

# Execute if running directly
if ($Node) {
    New-GPOFromNode -Node $Node
}