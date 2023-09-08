# Residues-check
This script searches for residual firewall rules, services, files, folders and registry keys left over from uninstalled programs.<br>
This script does not delete anything.

## Usage
To get examples and informations on the parameters, run the following command:
``` Powershell
Get-Help .\ResiduesCheck.ps1 -Detailed
```

## Output colors
Green values under a Blue path can be manually deleted but won't be opened, only the parent path will be opened.<br>
Green paths will be opened and can be manually deleted. The optional White values under specify which string triggered the match.
