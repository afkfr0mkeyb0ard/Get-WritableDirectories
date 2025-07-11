A Powershell script to get all writable folders and files with the current user on a Windows machine.

The script:
1. gets a list of all the folders on the system
2. checks the writable access for each folder by trying to write a `poc.txt` file
3. removes the `poc.txt` files

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
