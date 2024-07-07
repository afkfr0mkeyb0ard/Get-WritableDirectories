A Powershell script to get all writable folders with the current user on a Windows machine.

The script:
1. gets a list of all the folders on the system
2. checks the writable access for each folder by trying to write a `poc.txt` file
3. removes the `poc.txt` files

## Usage
```
PS> . .\Scanner.ps1
PS> Get-WritableDirectories -RootPath "C:\Windows\"
```
