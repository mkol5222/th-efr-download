
# all downloaded reports
$reports = gci ../efr-reports/*.zip

# harvest meta info from each forensics report
$malMeta = $reports | % { 
    $zipFile = $_.FullName
    $metaFile = Get-ZipEntries $zipFile | ? { $_.FullName -match '.+/json/malmeta_json.js'}
    $metaJson = Get-ZipEntryContent $zipFile $metaFile | select -Skip 3 | select -SkipLast 2

    $metaJson.Substring(0,$metaJson.Length-1) | ConvertFrom-Json 
}

$malMeta | select -First 1 | fl