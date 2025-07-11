A Powershell script to get all writable folders and files with the current user on a Windows machine.

The script:
-  gets a list of all the files and folders on the system
-  checks the write access for each folder by trying to write a `poc.txt` file and then removes it
-  checks the privileges for each file by trying to load them (read/write/execute)

## Usage
```
# Load the functions locally
PS> . .\functions.ps1

# Load the functions from the internet
PS> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/afkfr0mkeyb0ard/Get-WritableDirectories/refs/heads/main/functions.ps1');

# Check for writable files only
PS> Test-FileAccess -FilePaths (Get-AllFiles -Path "C:\Windows\System32") -Permission W | Format-Table -AutoSize

# Check for writable and executable files 
PS> Test-FileAccess -FilePaths (Get-AllFiles -Path "C:\Windows\System32") -Permission W,E | Format-Table -AutoSize

# Check for readable, writable and executable files 
PS> Test-FileAccess -FilePaths (Get-AllFiles -Path "C:\Windows\System32") -Permission R,W,E | Format-Table -AutoSize

# Check for writable folders
PS> Get-WritableDirectories -RootPath "C:\Windows\"
```
