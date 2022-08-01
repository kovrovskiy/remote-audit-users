$date1 = Get-Date -UFormat "%d.%m.%Y"
$date1 = $date1 + " 00:00:00"
$fRemote = "log_HostRemote.txt"
$fLock = "log_HostLock.txt"
$ParsServer = "srv-01"

New-Item -ItemType "file" -Name $fRemote -Force
New-Item -ItemType "file" -Name $fLock -Force

$s1 = New-PSSession -ComputerName srv-dc-01
Invoke-Command -Session $s1 {Get-ADUser -Identity $env:UserName | select Name | Set-Content D:\AD\TMP\$env:UserName".txt"}
#Disconnect-PSSession $s1

#[string]$fcs = Get-Content \\srv-dc-01\AD$\TMP\$env:UserName".txt" | ForEach-Object { $_ -replace "@{Name=", "" } | Set-Content $ftmp2
[string]$fcs = Get-Content \\srv-dc-01\AD$\TMP\$env:UserName".txt"
$fcs = $fcs -replace "}", ""
$fcs = $fcs -replace "@{Name=", ""
$fcs = $fcs -replace " ", "_"
$fcs | Set-Content \\srv-dc-01\AD$\TMP\$env:UserName".txt"

function Get-HostLogs{
	param( [string]$hostname, [string]$date )
	$filter = @{
		LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
		StartTime = [datetime]::parseexact($date, 'dd.MM.yyyy HH:mm:ss', $null) 
		}
    echo "Remote logon/logoff"
	
		$log = Get-WinEvent -ComputerName $hostname -FilterHashtable $filter `
			| where {($_.Id -eq "21" -OR $_.Id -eq "24" -OR $_.Id -eq "25"  -OR $_.Id -eq "23")} `
			
		$log | foreach {
			$logrecord = [xml]$_.ToXml()
			
			$username = $logrecord.Event.UserData.EventXML.User
			$useraction = 'error'
			switch ($logrecord.Event.System.EventID) {
				21 {$useraction = 'logon'; break}
				23 {$useraction = 'logoff'; break}
				24 {$useraction = 'logoff'; break}
				25 {$useraction = 'logon'; break}
				default {$useraction = 'error'}
				}
			$ip = $logrecord.Event.UserData.EventXML.Address
			$local = 'ЛОКАЛЬНЫЕ'
			#$local = $encTo.GetBytes($_)
			if ($ip -eq '' -Or $ip -eq $null -Or $ip -eq $local) {$ip = '0.0.0.0'}
			$insertdate = $logrecord.Event.System.TimeCreated.SystemTime
			$computername = $logrecord.Event.System.Computer
			    <#if ((test-connection -Count 1 -computer $ParsServer -quiet) -eq $True) {
                $url = 'http://'+$ParsServer+':94/log/write?login='+$username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
                $request = [System.Net.HttpWebRequest]::Create($url)
			    $response = $request.GetResponse()
				echo "Data sent to a remote server"
				echo $url >> $fRemote
                }
                else {
                $url = $username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
		   	    echo $url >> $fRemote
                echo "Data written to local file $fRemote"
                }#>
				$url = 'http://'+$ParsServer+':94/log/write?login='+$username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
				$url_local = $username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
                echo "Data written to local file $fRemote"
				echo $url >> $fRemote
				echo $url_local >> $fRemote
			}
		
	}

	
function Get-HostLogs-lock-Logoff{
	param( [string]$hostname, [string]$date )
	$filter = @{
		LogName = 'Security'
		StartTime = [datetime]::parseexact($date, 'dd.MM.yyyy HH:mm:ss', $null)
		Data = $env:UserName
		}
	    echo "PC Lock logoff"
		$log = Get-WinEvent -ComputerName $hostname -FilterHashtable $filter `
			| where {($_.Id -eq "4634" -and $_.properties[4].value -eq 3)} `
			
		#echo $log
		if ($log) {
			$log | foreach {
				$logrecord = [xml]$_.ToXml()
				
				$username = $logrecord.Event.EventData.Data[2].'#text'+'\'+$logrecord.Event.EventData.Data[1].'#text'				
				$useraction = 'error'
				switch ($logrecord.Event.System.EventID) {
					4634 {$useraction = 'logoff'; break}
					default {$useraction = 'error'}
					}
				$ip = $logrecord.Event.UserData.EventXML.Address
				<#if ($ip -eq '' -Or $ip -eq $null -Or $ip -eq $local) {$ip = '0.0.0.0'}
				$insertdate = $logrecord.Event.System.TimeCreated.SystemTime
				$computername = $logrecord.Event.System.Computer
			    if ((test-connection -Count 1 -computer $ParsServer -quiet) -eq $True) {
                $url = 'http://'+$ParsServer+':94/log/write?login='+$username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
                $request = [System.Net.HttpWebRequest]::Create($url)
			    $response = $request.GetResponse()
				echo "Data sent to a remote server"
				echo $url >> $fLock
                }
                else {                
                $url = $username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
		   	    echo $url >> $fLock
                echo "Data written to local file $fLock"
                    }#>
				$url = 'http://'+$ParsServer+':94/log/write?login='+$username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
				$url_local = $username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
                echo "Data written to local file $fLock"
				echo $url >> $fLock
				echo $url_local >> $fLock
				}
			}		
		
	}
	
	function Get-HostLogs-lock-Logon{
	param( [string]$hostname, [string]$date )
	$filter = @{
		LogName = 'Security'
		StartTime = [datetime]::parseexact($date, 'dd.MM.yyyy HH:mm:ss', $null)
		Data = $env:UserName		
		}
	    echo "PC Lock logon"
		$log = Get-WinEvent -ComputerName $hostname -FilterHashtable $filter `
			| where {($_.Id -eq "4624" -and $_.properties[8].value -eq 2) -OR ($_.Id -eq "4624" -and $_.properties[8].value -eq 10)} `
			
		#echo $log
		if ($log) {
			$log | foreach {
				$logrecord = [xml]$_.ToXml()
				
				$username = $logrecord.Event.EventData.Data[6].'#text'+'\'+$logrecord.Event.EventData.Data[5].'#text'				
				$useraction = 'error'
				switch ($logrecord.Event.System.EventID) {
					4624 {$useraction = 'logon'; break}
					4648 {$useraction = 'logon'; break}
					default {$useraction = 'error'}
					}
				$ip = $logrecord.Event.UserData.EventXML.Address
				if ($ip -eq '' -Or $ip -eq $null -Or $ip -eq $local) {$ip = '0.0.0.0'}
				$insertdate = $logrecord.Event.System.TimeCreated.SystemTime
				$computername = $logrecord.Event.System.Computer
			    <#if ((test-connection -Count 1 -computer $ParsServer -quiet) -eq $True) {
                $url = 'http://'+$ParsServer+':94/log/write?login='+$username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
                $request = [System.Net.HttpWebRequest]::Create($url)
			    $response = $request.GetResponse()
				echo "Data sent to a remote server"
				echo $url >> $fLock
                }
                else {                
                $url = $username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
		   	    echo $url >> $fLock
                echo "Data written to local file $fLock"
                    }#>
				$url = 'http://'+$ParsServer+':94/log/write?login='+$username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
				$url_local = $username+'&ip='+$ip+'&act='+$useraction+'&date='+$insertdate+'&hostname='+$computername+'&user='+$fcs
                echo "Data written to local file $fLock"
				echo $url >> $fLock
				echo $url_local >> $fLock
				}
			}		
		
	}

$list = "localhost"

$list | foreach {
	$dip = $_
	Get-HostLogs $dip $date1
	Get-HostLogs-lock-Logoff $dip $date1
	Get-HostLogs-lock-Logon $dip $date1
	}