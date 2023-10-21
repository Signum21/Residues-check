<#
.SYNOPSIS
This script searches for residual files, folders, registry keys, services, scheduled tasks and firewall rules left over from uninstalled programs.
The search is based on keywords provided by the user.
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
Possible values: All, Explorer, Regedit, Services, ScheduledTasks, FirewallRules
Default value: All

.PARAMETER MaxRegeditWindows
Max number of Regedit windows to open.
Default value: 1

.PARAMETER MaxExplorerWindows
Max number of Explorer windows to open.
Default value: 1

.PARAMETER ExcludeLongChecks
Option to exclude long checks.
Default value: False

.EXAMPLE
Performs all searches without opening any window.
.\ResiduesCheck.ps1 -Words anydesk,teamviewer -MaxExplorerWindows 0 -MaxRegeditWindows 0

.EXAMPLE
Perform Services and Regedit searches, opening only 1 window of Regedit.
.\ResiduesCheck.ps1 -Words openvpn -Check Services,Regedit -MaxRegeditWindows 1

.EXAMPLE
Perform all searches excluding the long ones, opening only 1 window of Regedit and only 1 windows of explorer, with maximum verbosity.
.\ResiduesCheck.ps1 -Words teamviewer -Check All -ExcludeLongChecks -v -d
#>


############################# Parameters #############################

Param(
	[Parameter(Position = 0, Mandatory = $true)]
	[String[]] $Words,
	
	[Parameter(Position = 1, Mandatory = $false)]
	[String] $FilePath = ".\paths.json",
	
	[Parameter(Position = 2, Mandatory = $false)]
	[ValidateSet("All", "Regedit", "Explorer", "Services", "ScheduledTasks", "FirewallRules")]
	[String[]] $Check = @("All"),
	
	[Parameter(Position = 3, Mandatory = $false)]
	[Int] $MaxRegeditWindows = 1,
	
	[Parameter(Position = 4, Mandatory = $false)]
	[Int] $MaxExplorerWindows = 1,
	
	[Parameter(Position = 5, Mandatory = $false)]
	[Switch] $ExcludeLongChecks = $false
)


############################# Global Functions #############################

function PrintHeader($header){
	$length = $header.Length
	
	$fullLine = $(foreach($i in (1..($length*3+2))){"#"}) -Join ""
	$blankLine = $("#" + $($(foreach($i in (1..($length*3))){" "}) -Join "") + "#")
	
	$halfBlankLine = $(foreach($i in (1..$length)){" "}) -Join ""
	$headerLine = $("#" + $halfBlankLine + $header + $halfBlankLine + "#")
	
	Write-Host $fullLine -ForegroundColor DarkRed
	Write-Host $blankLine -ForegroundColor DarkRed
	Write-Host $headerLine -ForegroundColor DarkRed
	Write-Host $blankLine -ForegroundColor DarkRed
	Write-Host $fullLine -ForegroundColor DarkRed
	Write-Host "`n" -NoNewline
}


############################# Explorer #############################

function OpenExplorerPaths($explorer_paths, $_words, $maxWindows, $_ExcludeLongChecks, $debugSwitch){
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
	
	if($explorer_paths){
		Write-Verbose "Checking Explorer paths `n`n"
		
		foreach($p in $explorer_paths){
			if($p.GetType().Name -eq "Object[]"){
				$p = GetFullPath($p)
			}
			
			if(Test-Path $p){
				Write-Debug $("Checking " + $p)
				$res = $(ls $p -Force -Recurse:(!$_ExcludeLongChecks) -ErrorAction SilentlyContinue).FullName | Select-String -Pattern $_words
				
				if($res){
					$explorerPathsToOpen += [pscustomobject]@{Key = $p; Value = @(); KeyColor="Blue"; ValueColor="Green"}
					
					foreach($r in $res){
						$explorerPathsToOpen[-1].Value += $r
					}	
				}
			}
			else{
				Write-Host $("Path {0} does not exist" -f $p) -BackgroundColor DarkRed
			}
		}
		
		if($debugSwitch){
			Write-Host "`n" -NoNewline
		}
	}
	else{
		Write-Verbose "Explorer paths missing `n`n"
	}
	
	if($explorerPathsToOpen){
		PrintHeader "Explorer paths"
		
		PrintPath $explorerPathsToOpen[0]
		OpenExplorer "explorer" $explorerPathsToOpen[0].Key $maxWindows ([ref]$windowsCounter)
		Start-Sleep -s 1
		$exp_paths = $explorerPathsToOpen[1..$explorerPathsToOpen.Length]
		
		foreach($epto in $exp_paths){
			PrintPath $epto
			OpenExplorer "ii" $epto.Key $maxWindows ([ref]$windowsCounter)
		}
	}
}


############################# Regedit #############################

function OpenRegeditPaths($regedit_folders_paths, $regedit_values_paths, $regedit_loops_paths, $_words, $maxWindows, $_ExcludeLongChecks, $debugSwitch){
	$windowsCounter = 0
	$firstPrint = $true
	
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
	
	function Local:Print($_regeditPathsToPrint, [ref]$_firstPrint){
		if($_regeditPathsToPrint){
			if($_firstPrint.Value){
				PrintHeader "Regedit paths"
				$_firstPrint.Value = $false
			}
				
			foreach($rptp in $regeditPathsToPrint){
				Write-Host $rptp.Key -ForegroundColor $rptp.KeyColor
				
				foreach($value in $rptp.Value){
					Write-Host $value -ForegroundColor $rptp.ValueColor
				}
				Write-Host "`n" -NoNewline
			}
		}
	}
	
	if($regedit_folders_paths){
		Write-Verbose "Checking Regedit folders paths `n`n"
		$regeditPathsToPrint = @()
		
		foreach($folder_path in $regedit_folders_paths){	
			if($folder_path.GetType().Name -eq "Object[]"){
				$sid = $(Get-LocalUser -Name $env:USERNAME).Sid.Value
				$folder_path = $folder_path[0] + $sid + $folder_path[2]
			}
			
			if(Test-Path Registry::$folder_path){
				Write-Debug $("Checking " + $folder_path)
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
			else{
				Write-Host $("Path {0} does not exist" -f $folder_path) -BackgroundColor DarkRed
			}
		}
	
		if($debugSwitch){
			Write-Host "`n" -NoNewline
		}
		Print $regeditPathsToPrint ([ref]$firstPrint)
	}
	else{
		Write-Verbose "Regedit folders paths missing `n`n"
	}
	
	if($regedit_values_paths){
		Write-Verbose "Checking Regedit values paths `n`n"
		$regeditPathsToPrint = @()
		
		foreach($value_path in $regedit_values_paths){		
			if($value_path.GetType().Name -eq "Object[]"){
				$sid = $(Get-LocalUser -Name $env:USERNAME).Sid.Value
				$value_path = $value_path[0] + $sid + $value_path[2]
			}
			
			if(Test-Path Registry::$value_path){
				Write-Debug $("Checking " + $value_path)
				$res = $(reg query $value_path)[2..$value_path.Length] | Select-String -Pattern $_words
				
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
			else{
				Write-Host $("Path {0} does not exist" -f $value_path) -BackgroundColor DarkRed
			}
		}
		
		if($debugSwitch){
			Write-Host "`n" -NoNewline
		}
		Print $regeditPathsToPrint ([ref]$firstPrint)
	}
	else{
		Write-Verbose "Regedit values paths missing `n`n"
	}
	
	if(!$_ExcludeLongChecks -and $regedit_loops_paths){
		Write-Verbose "Checking Regedit loops paths `n`n"
		$regeditPathsToPrint = @()
	
		foreach($loop_path in $regedit_loops_paths){
			if($loop_path.GetType().Name -eq "Object[]"){
				$sid = $(Get-LocalUser -Name $env:USERNAME).Sid.Value
				$loop_path = $loop_path[0] + $sid + $loop_path[2]
			}
			
			if(Test-Path Registry::$loop_path){
				$res = $(reg query $loop_path).Where({ $_ -ne "" -and $_.substring(0, 4) -ne "    " })
				
				foreach($r in $res){
					Write-Debug $("Checking " + $r)
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
			else{
				Write-Host $("Path {0} does not exist" -f $loop_path) -BackgroundColor DarkRed
			}
			
			if($debugSwitch){
				Write-Host "`n" -NoNewline
			}
		}
		Print $regeditPathsToPrint ([ref]$firstPrint)
	}
	elseif(!$regedit_loops_paths){
		Write-Verbose "Regedit loops paths missing `n`n"
	}
}


############################# Services #############################

function GetServices($_words){
	Write-Verbose "Checking Services `n`n"
	
	$filter = foreach($w in $_words) {"*$w*"}
	$services = @()
	$services += (Get-Service -Name $filter) 2>$null
	$services += (Get-Service -DisplayName $filter) 2>$null
	$services = $services | select -Unique -Property Name, DisplayName, Status
	
	if($services){
		PrintHeader "Services"
		
		Write-Host $($services | Format-List | Out-String).Trim() -NoNewline 2>$null
		
		Write-Host "`n"
		Write-Host "You can stop and delete any service using the following commands with admin privileges:"
		Write-Host "Stop-Service -Name " -ForegroundColor Blue -NoNewline
		Write-Host "<ServiceName>" -ForegroundColor DarkYellow
		Write-Host "sc.exe delete " -ForegroundColor Blue -NoNewline
		Write-Host "<ServiceName>" -ForegroundColor DarkYellow
		Write-Host "`n" -NoNewline
	}
}


############################# Scheduled Tasks #############################

function GetScheduledTasks($_words){
	Write-Verbose "Checking Scheduled Tasks `n`n"
	
	$filter = $_words -Join "|"
	
	$tasks = Get-ScheduledTask | where { 
		$_.URI -match $filter -or `
		$_.Author -match $filter -or `
		$_.Description -match $filter -or `
		$_.Actions.Execute -match $filter
	} | select TaskName,TaskPath,Author,Description,@{N='Actions';E={foreach($action in $_.Actions) { $action.Execute + " " + $action.Arguments }}}

	if($tasks){
		PrintHeader "Scheduled Tasks"
		
		Write-Host $($tasks | Format-List | Out-String).Trim() -NoNewline
		
		Write-Host "`n"
		Write-Host "You can delete any scheduled task using the following command:"
		Write-Host "Unregister-ScheduledTask -TaskName " -ForegroundColor Blue -NoNewline
		Write-Host "<TaskName>" -ForegroundColor DarkYellow
		Write-Host "`n" -NoNewline
	}	
}


############################# Firewall Rules #############################

function GetFirewallRules($_words){
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	
	if($isAdmin){
		Write-Verbose "Checking Firewall Rules `n`n"
		
		$filter = $_words -Join "|"
		
		$rules = Get-NetFirewallRule | where { 
			$_.Name -match $filter -or `
			$_.ID -match $filter -or `
			$_.DisplayName -match $filter -or `
			$_.Group -match $filter -or `
			$_.Description -match $filter -or `
			$_.ElementName -match $filter -or `
			$_.InstanceID -match $filter -or `
			$_.CreationClassName -match $filter -or `
			$_.DisplayGroup -match $filter -or `
			$_.RuleGroup -match $filter
		} | select Name,ID,DisplayName,Group,Description,ElementName,InstanceID,CreationClassName,DisplayGroup,RuleGroup,Enabled,Direction,Action
		
		if($rules){
			PrintHeader "Firewall Rules"
			
			Write-Host $($rules | Format-List | Out-String).Trim() -NoNewline
			
			Write-Host "`n"
			Write-Host "You can delete any firewall rule using the following command with admin privileges:"
			Write-Host "Remove-NetFirewallRule -DisplayName " -ForegroundColor Blue -NoNewline
			Write-Host "<RuleDisplayName>" -ForegroundColor DarkYellow
			Write-Host "`n" -NoNewline
		}
	}
	else{
		Write-Host "You need admin privileges to check firewall rules" -BackgroundColor DarkRed
	}	
}


############################# Main #############################

if ($PSBoundParameters["Debug"]) {
	$DebugPreference = "Continue"
}
$fileFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
$paths = Get-Content $FilePath -Raw 2>$null | ConvertFrom-Json
$regex = $Check -Join "|"

if("AllExplorer" -match $regex){
	if($paths){
		$exp_paths = if ($ExcludeLongChecks) { $paths.explorer_specific } else { $paths.explorer_recursive }
		OpenExplorerPaths $exp_paths $Words $MaxExplorerWindows $ExcludeLongChecks $PSBoundParameters["Debug"]
	}
	else{
		Write-Host $("Can't run Explorer check: {0} not found" -f $fileFullPath) -BackgroundColor DarkRed
		Write-Host "`n" -NoNewline
	}
}

if("AllRegedit" -match $regex){
	if($paths){
		OpenRegeditPaths $paths.regedit_folders $paths.regedit_values $paths.regedit_loops $Words $MaxRegeditWindows $ExcludeLongChecks $PSBoundParameters["Debug"]
	}
	else{
		Write-Host $("Can't run Regedit check: {0} not found" -f $fileFullPath) -BackgroundColor DarkRed
		Write-Host "`n" -NoNewline
	}
}

if("AllServices" -match $regex){
	GetServices $Words
}

if("AllScheduledTasks" -match $regex){
	GetScheduledTasks $Words
}

if("AllFirewallRules" -match $regex){
	GetFirewallRules $Words
}	