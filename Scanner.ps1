# Function to check if the current user has write permission on a given directory
function Test-WritePermission {
    param (
        [string]$DirectoryPath
    )
    $writeAccess = $false
    $filepath = Join-Path $DirectoryPath "poc.txt"
    try {
        echo "Poc" | Out-File $filepath
	$writeAccess = $true
	
    } catch {}

	if ($writeAccess){
	try{Remove-Item $filepath -ErrorAction Stop}
	catch{Write-Host "[!] Cannot remove file $filepath"}}
    return $writeAccess
}

# Function to get all directories recursively and check for write access
function Get-WritableDirectories {
    param (
        [string]$RootPath
    )
    $directories = Get-ChildItem $RootPath -Force -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName | Where { $_.StartsWith("C:\")}
    foreach ($dir in $directories) {
        if (Test-WritePermission -DirectoryPath $dir) {
            Write-Host $dir
        }
    }
}
