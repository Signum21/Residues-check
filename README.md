# Residues-check
This script searches for residual files, folders, registry keys, services, scheduled tasks and firewall rules left over from uninstalled programs.<br>
The search is based on keywords provided by the user.<br>
This script does not delete anything.

## Usage
To get examples and informations on the parameters, run the following command:
``` Powershell
Get-Help .\ResiduesCheck.ps1 -Detailed
```

## Output colors
Green values under a Blue path can be manually deleted.
Green paths can be manually deleted. The optional White values under specify which string triggered the match.

## Verbosity
You can use the \[-Verbose, -v] option to add basic verbosity and the \[-Debug, -d] option to add high verbosity.<br>
Use both to add mmaximum verbosity.