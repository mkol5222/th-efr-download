# Check Point Threat Hunting tools for PowerShell

### Install
```powershell
git clone https://github.com/mkol5222/th-efr-download.git
cd th-efr-download
. ./efrdown.ps1
```

### API keys
Get Threat Hunting and Harmony Endpoint keys in Infinity Portal and load variables before use
```powershell
$TH_KEY = "bring your own API keys"
$TH_SECRET = "and secrets"

$EP_KEY = "bring your own API keys"
$EP_SECRET = "and secrets"
```

### Download one Forensics Report from TH Incident View
```powershell
    # login with TH key to get list of incidents
    Write-Host "Login to Infinity Portal with TH key"
    New-CPPortalSession $TH_KEY $TH_SECRET | Out-Null
    # get list
    Write-Host "Getting list of incidents"
    $incidentList = (Get-CpThIncident).records 
    $count = ($incidentList | Measure-Object).Count
    Write-Host "Got $count records"
    # get ID of first one
    $iid = $incidentList | % { $_.DetectionEvent.DetectionIncidentId } | Select-Object -First 1 
    Write-Host "First incident ID is $iid"
    # API for forensics report download is EPM, login first with EP keys
    Write-Host "Login to Infinity Portal with EP key"
    New-CPPortalSession $EP_KEY $EP_SECRET | Out-Null
    # need session on EPM too; based on portal identity
    Write-Host "Login to EPM service"
    New-CpEpmSession | Out-Null
    # download report in base64 string
    Write-Host "Downloading report for IID $iid"
    $resp = Get-CpThIncidentReport $iid
    # decode and save to ZIP
    Write-Host "Saving report for IID $iid"
    Out-CpThIncidentReport $resp.incidentLog "$iid.zip"
    
    Write-Host "Download done. Look at $iid.zip"
    ls "$iid.zip"
```

### Display list of incidents with Forensics iid
```powershell
    # login with TH key to get list of incidents
    Write-Host "Login to Infinity Portal with TH key"
    New-CPPortalSession $TH_KEY $TH_SECRET | Out-Null
    # get list
    Write-Host "Getting list of incidents"
    $incidentList = (Get-CpThIncident).records 
    $incidentList | select MachineName, @{n = "ProcessName"; e = { $_.Base.ProcessName } }, 
        @{n = "Trigger"; e = { $_.DetectionEvent.DetectionTriggeredBy } }, 
        @{n = "ProtectionName"; e = { $_.DetectionEvent.DetectionProtectionName } },
        @{n = "iid"; e = { $_.DetectionEvent.DetectionIncidentId } }  
```

