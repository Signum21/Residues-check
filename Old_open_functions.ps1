function Local:OpenExplorer($cmdlet, $path_exp, $_maxWindows, [ref]$_windowsCounter){
	if($_maxWindows -gt $_windowsCounter.Value){
		$_windowsCounter.Value++
		&($cmdlet) $path_exp
	}
}

PrintPath $explorerPathsToOpen[0]
OpenExplorer "explorer" $explorerPathsToOpen[0].Key $maxWindows ([ref]$windowsCounter)
Start-Sleep -s 1
$exp_paths = $explorerPathsToOpen[1..$explorerPathsToOpen.Length]

foreach($epto in $exp_paths){
	PrintPath $epto
	OpenExplorer "ii" $epto.Key $maxWindows ([ref]$windowsCounter)
}

#####################################

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

OpenRegedit $reg $maxWindows ([ref]$windowsCounter)