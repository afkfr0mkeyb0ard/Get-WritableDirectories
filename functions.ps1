function Get-AllFiles {
    param (
        [string]$Path
    )

    $allFiles = @()

    if ($Path) {
        # Utilisateur a fourni un chemin personnalisé
        Write-Host "Scanning $Path ..."
        try {
            $allFiles += Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty FullName
        } catch {
            Write-Warning "Error accessing ${Path}: $_"
        }
    } else {
        # Parcourir tous les lecteurs si aucun chemin fourni
        $drives = (Get-PSDrive -PSProvider FileSystem).Name
        foreach ($drive in $drives) {
            $drivePath = "$drive`:\"
            Write-Host "Scanning $drivePath ..."
            try {
                $allFiles += Get-ChildItem -Path $drivePath -Recurse -File -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty FullName
            } catch {
                Write-Warning "Error accessing ${drivePath}: $_"
            }
        }
    }

    return $allFiles
}



function Test-FileWritable {
    param (
        [Parameter(Mandatory)]
        [string[]]$FilePaths
    )

    foreach ($file in $FilePaths) {
        $writable = $false

        try {
            $stream = [System.IO.File]::Open($file, 'Open', 'Write')
            $stream.Close()
            $writable = $true
        } catch {
            $writable = $false
        }

        [PSCustomObject]@{
            Path     = $file
            Writable = $writable
        }
    }
}

#List all the files on the system
#Get-AllFiles

#List all files in C:\Windows\System32
#Get-AllFiles -Path "C:\Windows\System32"

#Find all writable files in C:\Windows\System32
#Test-FileWritable -FilePaths (Get-AllFiles -Path "C:\Windows\System32") | Where-Object { $_.Writable }

