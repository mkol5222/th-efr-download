# .NET ZIP file support
[Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null

function isValidZipPath($Path) {
    if (-Not ($Path | Test-Path) ) {
        throw "File or folder does not exist"
    }
    if (-Not ($Path | Test-Path -PathType Leaf) ) {
        throw "The Path argument must be a file. Folder paths are not allowed."
    }
    if ($Path -notmatch "(\.zip)") {
        throw "The file specified in the path argument must be zip"
    }
    return $true 
}

# list of all files in archive
function Get-ZipEntries {
    param(
        [ValidateScript({
                return isValidZipPath($_)
            })]
        [System.IO.FileInfo]$Path
    )
    [IO.Compression.ZipFile]::OpenRead($Path).Entries
}

# extract archived file content to pipe
function Get-ZipEntryContent {
    param(
        [ValidateScript({
                return isValidZipPath($_)
            })]
        [System.IO.FileInfo]$zipFilename,
        [String]$entryFullname
    )
    $zip = [io.compression.zipfile]::OpenRead($zipFilename)
    if ($zip) {
        $files = ($zip.Entries | Where-Object { $_.FullName -eq $entryFullname })
        if (!$files) {
            throw "ZIP entry '${entryFullname}' not found"
        }
        $file = $files[0]
        if ($file) {
            $stream = $file.Open()
 
            $reader = New-Object IO.StreamReader($stream)
            while ( $text = $reader.ReadLine() ) {
                Write-Output $text
            }
       
            $reader.Close()
            $stream.Close()
        }
        else {
            throw "Unable to read '${entryFullname}' from ZIP"
        }
        $zip.Dispose()
    }
}