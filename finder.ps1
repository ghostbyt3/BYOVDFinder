<#
.SYNOPSIS
    Checks which drivers from loldrivers.io are NOT blocked by the current HVCI blocklist.
.DESCRIPTION
    This script helps you check which drivers from loldrivers.io are not blocked by the current HVCI (Hypervisor Code Integrity) blocklist on your system. 
    This is particularly useful for BYOVD (Bring Your Own Vulnerable Driver) attack paths where vulnerable drivers are permitted to load despite HVCI being enabled.
.AUTHOR
    Nikhil John Thomas (@ghostbyt3)
.LINK
    https://github.com/ghostbyt3/BYOVDFinder
.LICENSE
    Apache License 2.0
.PARAMETER XmlFile
    Optional path to the HVCI policy XML file to analyze. If not provided, the script
    will download CIPolicyParser and convert the system's current driversipolicy.p7b.
.EXAMPLE
    .\Finder.ps1 -XmlFile "C:\temp\driversipolicy.xml"
.EXAMPLE
    .\Finder.ps1
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$XmlFile
)

$LOLDIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
$CIPolicyParserUrl = "https://gist.githubusercontent.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e/raw/a9b55d31075f91b467a8a37b9d8b2d84a0aa856b/CIPolicyParser.ps1"
$TempXmlFile = "$env:TEMP\driversipolicy.xml"

Write-Host @"

      _____   _______   _____  ___ _         _         
     | _ ) \ / / _ \ \ / /   \| __(_)_ _  __| |___ _ _ 
     | _ \\ V / (_) \ V /| |) | _|| | ' \/ _` / -_) '_|
     |___/ |_| \___/ \_/ |___/|_| |_|_||_\__,_\___|_|  
                                                       
"@ -ForegroundColor Cyan

function Get-LolDrivers {
    try {
        Write-Host "[*] Downloading driver data from loldrivers.io..." -ForegroundColor Yellow
        $json = (New-Object System.Net.WebClient).DownloadString($LOLDIVERS_URL)
        Add-Type -AssemblyName System.Web.Extensions
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $serializer.MaxJsonLength = [int]::MaxValue
        $response = $serializer.DeserializeObject($json)
        
        $vulnerableSamples = @()
        
        foreach ($entry in $response) {
            if ($entry.ContainsKey('KnownVulnerableSamples') -and 
                $entry['KnownVulnerableSamples'] -and 
                $entry['KnownVulnerableSamples'].Count -gt 0) {
                
                foreach ($sample in $entry['KnownVulnerableSamples']) {
                    $sampleObj = [PSCustomObject]@{
                        MD5 = $sample['MD5']
                        SHA1 = $sample['SHA1']
                        SHA256 = $sample['SHA256']
                        OriginalFilename = $sample['OriginalFilename']
                        FileVersion = $sample['FileVersion']
                        Authentihash = $sample['Authentihash']
                        Signatures = $sample['Signatures']
                        _parent_driver = [PSCustomObject]@{
                            Id = $entry['Id']
                            Tags = $entry['Tags']
                            Category = $entry['Category']
                            MitreID = $entry['MitreID']
                        }
                    }
                    $vulnerableSamples += $sampleObj
                }
            }
        }
        
        return $vulnerableSamples
    }
    catch {
        Write-Host "[-] Error fetching loldrivers.io data: $_" -ForegroundColor Red
        exit 1
    }
}

function Get-PolicyData {
    param (
        [string]$XmlFile
    )
    
    try {
        if (-not (Test-Path $XmlFile)) {
            throw "[-] XML file not found at path: $XmlFile"
        }
        
        # Load and clean the XML content
        $content = Get-Content -Path $XmlFile -Raw
        $content = $content -replace 'xmlns(:ns)?="[^"]+"',''
        $xml = [xml]$content
        
        # Get file rules and signers from policy
        $file_rules = $xml.SiPolicy.FileRules
        $signers = $xml.SiPolicy.Signers.Signer
        
        return $file_rules, $signers
    }
    catch {
        Write-Host "[-] Error reading policy XML: $_" -ForegroundColor Red
        exit 1
    }
}

function Test-BlockedHash {
    param (
        [PSObject]$Driver,
        [System.Xml.XmlElement]$FileRules
    )
    
    foreach($hash in $file_rules.Deny.Hash){
        if(($hash) -and (
           ($hash -eq $Driver.Authentihash.SHA256) -or
           ($hash -eq $Driver.Authentihash.SHA1) -or 
           ($hash -eq $Driver.Authentihash.MD5) -or 
           ($hash -eq $Driver.SHA256) -or
           ($hash -eq $Driver.SHA1) -or 
           ($hash -eq $Driver.MD5)))
        {
            return $true
        }
    }
    return $false
}

function Test-BlockedSigner {
    param (
        [PSObject]$Driver,
        [System.Xml.XmlElement]$FileRules,
        [System.Xml.XmlElement[]]$Signers
    )
    
    $file_attrib = $file_rules.FileAttrib | Where-Object {$_.FileName -eq $Driver.OriginalFilename}

    foreach($signer in $Signers){
        $tbs = $signer.CertRoot.Value.ToLower()
        if(($Driver.Signatures.Certificates.TBS.MD5 -contains $tbs) -or
           ($Driver.Signatures.Certificates.TBS.SHA1 -contains $tbs) -or 
           ($Driver.Signatures.Certificates.TBS.SHA256 -contains $tbs) -or 
           ($Driver.Signatures.Certificates.TBS.SHA384 -contains $tbs)){
            $blocked_files = $signer.FileAttribRef
            if(!$blocked_files -or ($blocked_files.RuleID -contains $file_attrib.ID)){
                return $true
            }
        }
    }
    return $false
}

function Test-BlockedVersion {
    param (
        [PSObject]$Driver,
        [System.Xml.XmlElement]$FileRules
    )
    
    $file_max_version = ($file_rules.Deny | Where-Object {$_.FileName -eq $Driver.OriginalFilename}).MaximumFileVersion
    $version = (-split ($Driver.FileVersion -replace ',\s*', '.'))[0]
    
    if($file_max_version -and $version -and ([version]$version -le $file_max_version)){
        return $true
    }
    return $false
}

function Write-DriverInfo {
    param (
        [PSObject]$Driver
    )
    
    $parent = $Driver._parent_driver
    $link = if ($parent.Id) { "https://www.loldrivers.io/drivers/$($parent.Id)" } else { "N/A" }
    $name = if ($Driver.OriginalFilename) { $Driver.OriginalFilename } else { $parent.Tags -join '' }
    
    Write-Host "DRIVER: $(if ($name) { $name } else { 'Unknown' })" -ForegroundColor Red
    Write-Host "  Link: $link" -ForegroundColor Green
    
    if ($Driver.MD5) { Write-Host "  MD5: $($Driver.MD5)" }
    if ($Driver.SHA1) { Write-Host "  SHA1: $($Driver.SHA1)" }
    if ($Driver.SHA256) { Write-Host "  SHA256: $($Driver.SHA256)" }
    
    if ($Driver.FileVersion) { Write-Host "  Version: $($Driver.FileVersion)" }
    
    Write-Host ("-" * 80)
}

# Main execution
try {
    # Get driver data
    $drivers = Get-LolDrivers
    
    # Get policy data
    if (-not $XmlFile) {
        Write-Host "[*] No XML file provided, using system policy..." -ForegroundColor Yellow
        
        $policyScript = "$env:TEMP\CIPolicyParser.ps1"
        try {
            (New-Object System.Net.WebClient).DownloadString($CIPolicyParserUrl) | Out-File $policyScript
            . $policyScript
            ConvertTo-CIPolicy -BinaryFilePath 'C:\Windows\System32\CodeIntegrity\driversipolicy.p7b' -XmlFilePath $TempXmlFile | Out-Null
            $XmlFile = $TempXmlFile
        }
        finally {
            if (Test-Path $policyScript) {
                Remove-Item $policyScript -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    
    $file_rules, $signers = Get-PolicyData $XmlFile
    
    # Analyze drivers
    $blocked = 0
    $allowed = 0
    $allowed_drivers = @()
    
    foreach ($driver in $drivers) {
        if ((Test-BlockedHash $driver $file_rules) -or 
            (Test-BlockedSigner $driver $file_rules $signers) -or 
            (Test-BlockedVersion $driver $file_rules)) {
            $blocked++
        } 
        else {
            $allowed++
            $allowed_drivers += $driver
        }
    }
    
    Write-Host "`n"
    foreach ($driver in $allowed_drivers) {
        Write-DriverInfo $driver
    }

    # Display results
    Write-Host "`n[+] Number of Blocked Drivers: $blocked" -ForegroundColor Cyan
    Write-Host "[+] Number of Allowed (Potentially Vulnerable) Drivers: $allowed`n" -ForegroundColor Cyan
}
finally {
    # Clean up temporary files
    $filesToRemove = @(
        $TempXmlFile
        "$env:TEMP\CIPolicyParser.ps1"
    )
    
    foreach ($file in $filesToRemove) {
        if (Test-Path $file) {
            Remove-Item $file -Force -ErrorAction SilentlyContinue
        }
    }
}