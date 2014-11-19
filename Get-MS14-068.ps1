##################################################
#### Scan Security Log for possible MS14068 ######
##################################################

#Enable the line below to scan ALL DC's in a domain - this will be slow
#$dclist = [system.directoryservices.activedirectory.domain]::GetCurrentDomain() | ForEach-Object {$_.DomainControllers} | ForEach-Object {$_.Name} 
$dclist = "domaincontrollername"
$attacks = 0
$maxevents = 1000
$adminuser = "domain\admin"

if (-not $AdminCredentials) {
	$AdminCredentials = Get-Credential -Message "Enter credentials with access to security log"
}

foreach ($dc in $dclist) {

	Write-Host "Checking $dc"

	$events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4624} -MaxEvents $maxevents -Credential $AdminCredentials -ComputerName $dc

	Write-Host "Found " $events.Count " EventID 4624 events..." 

	foreach ($event in $events) {
		$evtxml = [xml]$event.ToXML()
		$sid = [String]$evtxml.Event.EventData.Data[4].'#text'
		$user = [String]$evtxml.Event.EventData.Data[5].'#text'
		$domain = [String]$evtxml.Event.EventData.Data[6].'#text'
	
		$ntaccount = New-Object System.Security.Principal.NTAccount($domain, $user)
		$usersid = $ntaccount.Translate([System.Security.Principal.SecurityIdentifier])
		
		if ($sid -ne "S-1-5-18") {
			if ($sid -ne $usersid.Value) {
				$attacks++
				Write-Host "ERROR: Possible Attack!"
				write-host "Username: $user"
				write-host "SID: $sid"
				write-host "Translate SID:  $usersid"
				write-host "Domain: $domain"
			}
		}
	}
}
Write-Host "Attacks found: " $attacks