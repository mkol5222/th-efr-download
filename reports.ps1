
# all downloaded reports
$reports = gci ../efr-reports/*.zip

# harvest meta info from each forensics report
$malMeta = $reports | % { 
    $zipFile = $_.FullName
    if ($_.Size -gt 0) {
        Write-Host "Processing $zipFile"
        #Get-ZipEntries $_ | % { Write-Host $_.FullName }

        #$metaFile = Get-ZipEntries $_ | ? { $_.FullName -match '.+/json/malmeta_json.js' }
        #$metaJson = Get-ZipEntryContent $zipFile $metaFile | select -Skip 3 | select -SkipLast 2
        #if ($metaJson) { $metaJson.Substring(0, $metaJson.Length - 1) | ConvertFrom-Json }
        
        $suspJsonFile = Get-ZipEntries $_ | ? { $_.FullName -match '.+/json/susp_json.js' }
        $suspJson = Get-ZipEntryContent $zipFile $suspJsonFile | select -Skip 3 | select -SkipLast 2
        if ($suspJson) { 
            #Write-Host $suspJson
            $suspJson.Substring(0, $suspJson.Length - 1) | ConvertFrom-Json 
        }
    }
}

$malMeta | group-object cat | % {
    [PSCustomObject]@{
        Activity = $_.Group[0].cat;
        Description = $_.Group[0].d;
        Count = $_.Count;
    }
}