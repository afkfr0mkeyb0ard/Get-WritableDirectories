A Powershell script to get all writable folders with the current user on a Windows machine.

The script:
1. gets a list of all the folders on the system
2. checks the writable access for each folder by trying to write a `poc.txt` file
3. removes the `poc.txt` files

## Usage
```
PS> . .\Scanner.ps1
PS> Get-WritableDirectories -RootPath "C:\Windows\"

#Oneliner
> powershell -ep bypass -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/afkfr0mkeyb0ard/Get-WritableDirectories/refs/heads/main/Scanner.ps1');Get-WritableDirectories -RootPath C:\Windows\;"
```
