<#
.SYNOPSIS
This script searches for residual firewall rules, services, files, folders and registry keys left over from uninstalled programs.
This script does not delete anything.

.DESCRIPTION
Green values under a Blue path can be manually deleted but won't be opened, only the parent path will be opened.
Green paths will be opened and can be manually deleted. The optional White values under specify which string triggered the match.

.PARAMETER FilePath
Path to the JSON file containing the paths to analyze.
Default value: .\paths.json

.PARAMETER Words
Keywords used to filter results, case insensitive.

.PARAMETER Check
Option to specify which search to perform.
Possible values: All, Explorer, Regedit, Services, FirewallRules
Default value: All

.PARAMETER MaxRegeditWindows
Max number of Regedit windows to open.
Default value: 1

.PARAMETER MaxExplorerWindows
Max number of Explorer windows to open.
Default value: 1

.EXAMPLE
Performs all searches without opening any window.
.\ResiduesCheck.ps1 -Words anydesk,teamviewer -MaxExplorerWindows 0 -MaxRegeditWindows 0

.EXAMPLE
Perform Services and Regedit search opening only 1 window of Regedit.
.\ResiduesCheck.ps1 -Words openvpn -Check Services,Regedit -MaxRegeditWindows 1
#>


############################# Parameters #############################

Param(
	[Parameter(Position = 0, Mandatory = $true)]
	[String[]] $Words,
	
	[Parameter(Position = 1, Mandatory = $false)]
	[String] $FilePath = ".\paths.json",
	
	[Parameter(Position = 2, Mandatory = $false)]
	[ValidateSet("All", "Regedit", "Explorer", "Services", "FirewallRules")]
	[String[]] $Check = @("All"),
	
	[Parameter(Position = 3, Mandatory = $false)]
	[Int] $MaxRegeditWindows = 1,
	
	[Parameter(Position = 4, Mandatory = $false)]
	[Int] $MaxExplorerWindows = 1
)


############################# Regedit #############################

function OpenRegeditPaths($regedit_folders_paths, $regedit_values_paths, $regedit_loops_paths, $_words, $maxWindows){
	$windowsCounter = 0
	$regeditPathsToPrint = @()
	
	function Local:OpenRegedit($_path, $_maxWindows, [ref]$_windowsCounter){
		if($_maxWindows -gt $_windowsCounter.Value){
			$_windowsCounter.Value++
			$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
			$name = "LastKey"
			New-ItemProperty -Path $regPath -Name $name -Value $_path -PropertyType String -Force | Out-Null
			Start-Process RegEdit /m
			Start-Sleep -s 1
		}
	}
	
	foreach($folder_path in $regedit_folders_paths){
		if($folder_path.GetType().Name -eq "Object[]"){
			$sid = $(Get-LocalUser -Name $env:USERNAME).Sid.Value
			$folder_path = $folder_path[0] + $sid + $folder_path[2]
		}
		$res = reg query $folder_path | Select-String -Pattern $_words
		
		if($res){			
			$regeditPathsToPrint += [pscustomobject]@{Key = ""; Value = @(); KeyColor="Green"}
			
			foreach($r in $res){
				$regeditPathsToPrint[-1].Key += $([string]$r) + "`n"
				OpenRegedit $r $maxWindows ([ref]$windowsCounter)
			}
			$regeditPathsToPrint[-1].Key = $regeditPathsToPrint[-1].Key.Trim()
		}
	}
	
	foreach($value_path in $regedit_values_paths){
		if($value_path.GetType().Name -eq "Object[]"){
			$sid = $(Get-LocalUser -Name $env:USERNAME).Sid.Value
			$value_path = $value_path[0] + $sid + $value_path[2]
		}		
		$res = reg query $value_path | Select-String -Pattern $_words
		
		if($res){
			$regeditPathsToPrint += [pscustomobject]@{Key = $value_path; Value = @(); KeyColor="Blue"; ValueColor="Green"}
			OpenRegedit $value_path $maxWindows ([ref]$windowsCounter)
			
			foreach($r in $res){					
				foreach($match in $r){
					$value = $($([string]$match).Trim() -Split "    ")[0]
					$regeditPathsToPrint[-1].Value += $value
				}
			}
		}
	}
	
	foreach($loop_path in $regedit_loops_paths){
		if($loop_path.GetType().Name -eq "Object[]"){
			$sid = $(Get-LocalUser -Name $env:USERNAME).Sid.Value
			$loop_path = $loop_path[0] + $sid + $loop_path[2]
		}		
		$res = $(reg query $loop_path).Where({ $_ -ne "" -and $_.substring(0, 4) -ne "    " })
		
		foreach($r in $res){
			$res2 = reg query $r | Select-String -Pattern $_words
			
			if($res2){					
				$regeditPathsToPrint += [pscustomobject]@{Key = $r; Value = @(); KeyColor="Green"; ValueColor="White"}
				OpenRegedit $r $maxWindows ([ref]$windowsCounter)
				
				foreach($r2 in $res2){
					$regeditPathsToPrint[-1].Value += $([string]$r2).Trim() -Split "    " | Select-String -Pattern $_words
				}
			}
		}	
	}
	
	if($regeditPathsToPrint){
		Write-Host "Regedit paths:" -ForegroundColor DarkRed
		Write-Host "`n" -NoNewline
			
		foreach($rptp in $regeditPathsToPrint){
			Write-Host $rptp.Key -ForegroundColor $rptp.KeyColor
			
			foreach($value in $rptp.Value){
				Write-Host $value -ForegroundColor $rptp.ValueColor
			}
			Write-Host "`n" -NoNewline
		}
	}
}


############################# Explorer #############################

function OpenExplorerPaths($explorer_paths, $_words, $maxWindows){
	$windowsCounter = 0
	$explorerPathsToOpen = @()
	
	function Local:GetFullPath($obj){
		return [environment]::ExpandEnvironmentVariables("%" + $obj[0] + "%" + $obj[1])
	}
	
	function Local:OpenExplorer($cmdlet, $path_exp, $_maxWindows, [ref]$_windowsCounter){		
		if($_maxWindows -gt $_windowsCounter.Value){
			$_windowsCounter.Value++
			&($cmdlet) $path_exp
		}
	}
	
	function Local:PrintPath($_path){
		Write-Host $_path.Key -ForegroundColor $_path.KeyColor
			
		foreach($value in $_path.Value){
			Write-Host $value -ForegroundColor $_path.ValueColor
		}
		Write-Host "`n" -NoNewline
	}
	
	foreach($p in $explorer_paths){
		if($p.GetType().Name -eq "Object[]"){
			$p = GetFullPath($p)
		}
		$res = $(ls $p).Name | Select-String -Pattern $_words
		
		if($res){
			$explorerPathsToOpen += [pscustomobject]@{Key = $p; Value = @(); KeyColor="Blue"; ValueColor="Green"}
			
			foreach($r in $res){
				$explorerPathsToOpen[-1].Value += $r
			}	
		}
	}
	
	if($explorerPathsToOpen){
		Write-Host "Explorer paths:" -ForegroundColor DarkRed
		Write-Host "`n" -NoNewline
		
		PrintPath($explorerPathsToOpen[0])
		OpenExplorer "explorer" $explorerPathsToOpen[0].Key $maxWindows ([ref]$windowsCounter)
		Start-Sleep -s 1
		$exp_paths = $explorerPathsToOpen[1..$explorerPathsToOpen.Length]
		
		foreach($epto in $exp_paths){
			PrintPath($epto)
			OpenExplorer "ii" $epto.Key $maxWindows ([ref]$windowsCounter)
		}
	}
}


############################# Services #############################

function GetServices($_words){
	$filter = foreach($w in $_words) {"*$w*"}
	$nameFilter = (Get-Service -Name $filter) 2> $null
	$displayNameFilter = (Get-Service -DisplayName $filter) 2> $null
	$services = $nameFilter + $displayNameFilter | select -Unique -Property Name, DisplayName, Status
	
	if($services){
		Write-Host "Services:" -ForegroundColor DarkRed
		Write-Host "`n" -NoNewline
		
		Write-Host $($services | Format-List | Out-String).Trim() -NoNewline 2> $null
		
		Write-Host "`n"
		Write-Host "You can stop and delete any service using the following commands with admin privileges:"
		Write-Host "Stop-Service -Name " -ForegroundColor DarkCyan -NoNewline
		Write-Host "<ServiceName>" -ForegroundColor DarkYellow
		Write-Host "sc.exe delete " -ForegroundColor DarkCyan -NoNewline
		Write-Host "<ServiceName>" -ForegroundColor DarkYellow
		Write-Host "`n" -NoNewline
	}
}


############################# Firewall Rules #############################

function GetFirewallRules($_words){
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	
	if($isAdmin){
		$filter = foreach($w in $_words) {"*$w*"}
		$rules = Get-NetFirewallRule -DisplayName $filter | select DisplayName,Description,Enabled,Direction,Action
		
		if($rules){
			Write-Host "Firewall Rules:" -ForegroundColor DarkRed
			Write-Host "`n" -NoNewline
			
			Write-Host $($rules | Format-List | Out-String).Trim() -NoNewline
			
			Write-Host "`n"
			Write-Host "You can delete any rule using the following command with admin privileges:"
			Write-Host "Remove-NetFirewallRule -DisplayName " -ForegroundColor DarkCyan -NoNewline
			Write-Host "<RuleDisplayName>" -ForegroundColor DarkYellow
			Write-Host "`n" -NoNewline
		}
	}
	else{
		Write-Host "You need admin privileges to check firewall rules" -BackgroundColor DarkRed
	}		
}


############################# Main #############################

$paths = Get-Content $FilePath -Raw | ConvertFrom-Json

if("AllExplorer" -match $($Check -Join "|")){
	OpenExplorerPaths $paths.explorer $Words $MaxExplorerWindows
}

if("AllRegedit" -match $($Check -Join "|")){
	OpenRegeditPaths $paths.regedit_folders $paths.regedit_values $paths.regedit_loops $Words $MaxRegeditWindows
}

if("AllServices" -match $($Check -Join "|")){
	GetServices $Words
}

if("AllFirewallRules" -match $($Check -Join "|")){
	GetFirewallRules $Words
}