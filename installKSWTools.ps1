$userISEProfile = "$env:HOME\Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1"
$userPSProfile = "$env:HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"

Clear-Host
"This script edits your PowerShell profile by adding custom content to it that will load PowerShell modules and scripts from a desired path."
"If you are using this script to install kswtools, place the kswtools.psm1 file into the desired directory."
"If this is not what you want, please exit this script now, or else press any key to continue."


if (!(Test-Path $userPSProfile)) {
    Write-Host "`nProfile does not exist. Creating Profile."
    New-Item -type file -Force $userPSProfile
    Write-Host "`nProfile Created"
}
""
$psdir = Read-Host "Please enter the directory that you would like your PowerShell scripts to load from"

While (!(Test-Path $psdir)) {
    $psdir = Read-Host "The given location is not valid or does not exist. Please enter another location"
}

Write-Host "`nAdding custom PowerShell environment to your terminal profile..."
try {
    Add-Content $userPSProfile "Get-ChildItem `"${psdir}\*.ps*1`" | %{.`$_} "
    Add-Content $userPSProfile "Write-Host `"Custom PowerShell Environment Loaded`""
    Write-Host "Your custom Powershell environment has been added to your terminal profile."
}
catch [System.Exception] {
    Write-Warning "There was an error writing to your local profile.`nPlease take a look at ${profile} and see if anything is wrong"    
}

$iseProfile = Read-Host "`nWould you like to add the Custom Powershell environment to your ISE profile? (y or n)"


if ($iseProfile -eq "y") {
    if (!(Test-Path $userISEProfile)) {
        Write-Host "`nProfile does not exist.`nCreating Profile."
        New-Item -type file -Force $userISEProfile
        Write-Host "Profile Created`n"
    }

    try {
        Add-Content $userISEProfile "Get-ChildItem `"${psdir}\*.ps*1`" | %{.`$_} "
        Add-Content $userISEProfile "Write-Host `"Custom PowerShell Environment Loaded`""
        Write-Host "Your custom Powershell environment has been added to your ISE profile."
    }
    catch [System.Exception] {
        Write-Warning "There was an error writing to your local profile.`nPlease take a look at ${userISEProfile} and see if anything is wrong"    
    }
}

"Your Powershell profile "