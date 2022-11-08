
<#PSScriptInfo

.VERSION 1.4.2

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR HAO BAN/banhao@gmail.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI 

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
	Creation Date:  <11/08/2022>
	Purpose/Change: 

.PRIVATEDATA

.SYNOPSIS

.EXAMPLE

.DESCRIPTION secureX.ps1

#>

$SECUREX_CLIENT_ID = Get-Content .\init.conf | findstr SECUREX_CLIENT_ID |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$SECUREX_CLIENT_PASSWORD = Get-Content .\init.conf | findstr SECUREX_CLIENT_PASSWORD |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }

$TenantId = Get-Content .\init.conf | findstr TenantId |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$appId = Get-Content .\init.conf | findstr appId |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$appSecret = Get-Content .\init.conf | findstr appSecret |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }

function Threat_Response_authentication {
	$oAuthUri = "https://visibility.amp.cisco.com/iroh/oauth2/token"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", "Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SECUREX_CLIENT_ID + ":" + $SECUREX_CLIENT_PASSWORD)))")
	$headers.Add("Content-Type", "application/x-www-form-urlencoded")
	$headers.Add("Accept", "application/json")

	$authBody = @{
		grant_type = 'client_credentials'
	}

	$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Headers $headers -Body $authBody -ErrorAction Stop
	$global:Threat_Response_token = $authResponse.access_token
	$global:Threat_Response_tokenexpire = $authResponse.expires_in
}

function MDATP_authentication {
	$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
	$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
	$authBody = [Ordered] @{
		resource = "$resourceAppIdUri"
		client_id = "$appId"
		client_secret = "$appSecret"
		grant_type = 'client_credentials'
	}
	$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
	$global:MDATP_token = $authResponse.access_token
	$global:MDATP_tokenexpire = $authResponse.expires_on
}

function SecureX-Investigation {
	Threat_Response_authentication
	Write-OutPut "SecureX Investigation: " 
	$headers = @{
		'Content-Type' = 'application/json'
		Accept = 'application/json'
		Authorization = "Bearer $Threat_Response_token"
	}
	$body = ConvertTo-Json -InputObject @{ 'content' = $CONTENT }
	$inspect_response = Invoke-WebRequest -Method Post -Uri "https://visibility.amp.cisco.com/iroh/iroh-inspect/inspect" -Headers $headers -Body $body -ErrorAction Stop
	$headers = @{
		'Content-Type' = 'application/json'
		Accept = 'application/json'
		Authorization = "Bearer $Threat_Response_token"
	}
	$body = $inspect_response.Content
	$response = Invoke-WebRequest -Method Post -Uri "https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables" -Headers $headers -Body $body -ErrorAction Stop
	$results = $response.Content | ConvertFrom-Json
	for($i=0;$i -le $results.data.length;$i++){
		$module = $results.data[$i].module
		if ( $module -eq  "Talos Intelligence" ) {
			Write-OutPut "*********************************************"
			Write-OutPut "* Talos Intelligence Investigation Results: " 
			Write-OutPut "*********************************************"
			foreach ( $talos_results in $results.data[$i].data.verdicts.docs ){
				$ta_result = $talos_results.observable.value+" , "+$talos_results.disposition_name
				if ( ($talos_results.disposition_name -eq "Malicious") -or ($talos_results.disposition_name -eq "Suspicious") ) { $enable_alert = $true } 
				Write-OutPut $ta_result 
			}
			Write-OutPut ""
			Write-OutPut ""
		}
		if ( ($module -eq  "Umbrella") -and (![string]::IsNullOrEmpty($results.data[$i].data.sightings)) ) {
			$title = "* Umbrella Investigation Results, " + $($results.data[$i].data.sightings.docs[0].description -split 'by', 0)[0] + "by:"
			Write-OutPut "*********************************************"
			Write-OutPut $title 
			Write-OutPut "*********************************************"
			$_endpoint_list = @()
			$endpoint_list = @()
			foreach ($umbrella_results in $results.data[$i].data.sightings.docs){
				$_endpoint = $($umbrella_results.description -split 'by', 0)[1]
				$_endpoint_list += $_endpoint
			}
			$_endpoint_list = $_endpoint_list | sort -u
			Write-OutPut $_endpoint_list
			foreach ( $endpoint in $_endpoint_list ) {
				if ( $endpoint -like '*(AD Users)' ) {
					$regex = [regex]"\(\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*\)"
					$fRegion_EmailAddress = $($regex.match($endpoint)).Value.trimstart("(").trimend(")")
					$fRegion_DomainName = $($fRegion_EmailAddress -split '@',0)[1] 
					$GivenName = $($($($endpoint -split "\(" , 0)[0] -split "," , 0)[1] -split ' ', 0)[1]
					$Surname = $($($endpoint -split "\(" , 0)[0] -split "," , 0)[0].Trim().trimstart("'")
#					Write-OutPut "$($GivenName) $($Surname), $($fRegion_DomainName)"
					$ADUser_Properties = Get-ADUser -Filter 'GivenName -eq $GivenName -and Surname -eq $Surname' -Server $(Get-ADDomainController -DomainName $fRegion_DomainName -Discover -NextClosestSite).Name -properties *
					$SamAccountName = $ADUser_Properties.SamAccountName.ToLower()
					$Recipient = $ADUser_Properties.DisplayName
					$url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
					MDATP_authentication
					$headers = @{
								'Content-Type' = 'application/json'
								Accept = 'application/json'
								Authorization = "Bearer $MDATP_token"
								}
					$query = @"
DeviceNetworkEvents 
| where RemoteUrl contains "$CONTENT" and InitiatingProcessAccountName == "$SamAccountName"
"@
					$body = ConvertTo-Json -InputObject @{ 'Query' = $query }
					$response = Invoke-WebRequest -Method POST -Uri $url -Headers $headers -Body $body -ErrorAction Stop
					if ( ![string]::IsNullOrEmpty($(($response | ConvertFrom-Json).Results)) ) {
						Write-OutPut "MDATP found the User $($Recipient) tried to access the URL"
						$InitiatingProcessFileName = ($response | ConvertFrom-Json).Results.InitiatingProcessVersionInfoFileDescription
						$Timestamp = ($response | ConvertFrom-Json).Results.Timestamp
						$EmailBody = @"
Hello $Recipient,
Our security system detected you used $InitiatingProcessFileName to access [$CONTENT] at $Timestamp which is a Malicious/Phishing site. Please contact the Service Desk and change you AD account password immediately.
If you have any questions, please contact ehssecurity@ehealthsask.ca

Thanks,
Enterprise Security Services
eHealth Saskatechewan 
"@
						if ( $enable_alert -eq $true) { 
							if ( ![string]::IsNullOrEmpty($ADUser_Properties.EmailAddress) ) {
								Send-MailMessage -SmtpServer relay-partner.ehealthsask.ca -To $ADUser_Properties.EmailAddress -From "EMAILADDRESS" -Cc "EMAILADDRESS" -Subject "Security Alert" -Body $EmailBody
								Write-OutPut "Alert Message has been sent to $($Recipient)"
							}else{ Write-OutPut "$($Recipient) Email Address is not exist." }	
						}
					} else { Write-OutPut "No related result was found in MDATP for $($Recipient)" }
				}
				if ( $endpoint -like '*(Anyconnect Roaming Client)' ) {
					$endpoint_list += $($endpoint -split ' ', 0)[1].trimstart("'").trimend("'")
					$HOSTNAME = $($endpoint -split ' ', 0)[1].trimstart("'").trimend("'")
					$url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
					MDATP_authentication
					$headers = @{
								'Content-Type' = 'application/json'
								Accept = 'application/json'
								Authorization = "Bearer $MDATP_token"
								}
					$query = @"
DeviceInfo 
| where DeviceName startswith "$HOSTNAME"
| summarize count() by DeviceId	
"@
					$body = ConvertTo-Json -InputObject @{ 'Query' = $query }
					$response = Invoke-WebRequest -Method POST -Uri $url -Headers $headers -Body $body -ErrorAction Stop
					$DeviceId = ($response | ConvertFrom-Json).Results.DeviceId
					$query = @"
DeviceNetworkEvents 
| where DeviceId == "$DeviceId" and RemoteUrl contains "$CONTENT"
| where Timestamp > ago(30d)		
"@
					$body = ConvertTo-Json -InputObject @{ 'Query' = $query }
					$response = Invoke-WebRequest -Method POST -Uri $url -Headers $headers -Body $body -ErrorAction Stop
					if ( ![string]::IsNullOrEmpty($(($response | ConvertFrom-Json).Results)) ) {
						Write-OutPut "MDATP found the Endpoint $($HOSTNAME) tried to access the URL"
						$UserPrincipalName = ($response | ConvertFrom-Json).Results.InitiatingProcessAccountUpn
						if ( !([string]::IsNullOrEmpty($UserPrincipalName) -or [string]::IsNullOrWhiteSpace($UserPrincipalName)) ) {
							$UserPrincipalName = ($response | ConvertFrom-Json).Results.InitiatingProcessAccountName
						}
						$InitiatingProcessFileName = ($response | ConvertFrom-Json).Results.InitiatingProcessVersionInfoFileDescription
						$Timestamp = ($response | ConvertFrom-Json).Results.Timestamp
						$computerDnsName = ($response | ConvertFrom-Json).Results.DeviceName
						$DomainName = $($UserPrincipalName -split '@',0)[1]
						$Identity = $($UserPrincipalName -split '@',0)[0]
						$ADUser_Properties = Get-ADUser -Identity $Identity -Server $(Get-ADDomainController -DomainName $DomainName -Discover -NextClosestSite).Name -properties *
						$Recipient = $ADUser_Properties.DisplayName
						$EmailBody = @"
Hello $Recipient,
Our security system detected you used $InitiatingProcessFileName to access [$CONTENT] at $Timestamp which is a Malicious/Phishing site. Please contact the Service Desk and change you AD account password immediately.
If you have any questions, please contact ehssecurity@ehealthsask.ca

Thanks,
Enterprise Security Services
eHealth Saskatechewan 
"@
						if ( $enable_alert -eq $true) { 
							if ( ![string]::IsNullOrEmpty($ADUser_Properties.EmailAddress) ) {
								Send-MailMessage -SmtpServer relay-partner.ehealthsask.ca -To $ADUser_Properties.EmailAddress -From "EMAILADDRESS" -Cc "EMAILADDRESS" -Subject "Security Alert" -Body $EmailBody
								Write-OutPut "Alert Message has been sent to $($HOSTNAME)"
							}else{ Write-OutPut "$($Recipient) Email Address is not exist." }
						}
					} else { Write-OutPut "No related result was found in MDATP for HOST $($HOSTNAME)" }
				}	
			}
			Write-OutPut ""
			Write-OutPut ""
			
		}
		if ( $module -eq  "SMA Email" ) {
			Write-OutPut "*********************************************"
			Write-OutPut "* SMA Email Investigation Results, Following e-mail address were related to the URLs/Domains:" 
			Write-OutPut "*********************************************"
			$Outgoing_list = @()
			$Incoming_list = @()
			for($j=0;$j -le $results.data[$i].data.sightings.docs.length;$j++){
				if ($results.data[$i].data.sightings.docs[$j].description -match "Outgoing"){
					$email_mid = foreach($key in $($results.data[$i].data.sightings.docs[$j].relations.related | where-Object {$_.type -eq "cisco_mid"})){$key.value}
					$email_subject = foreach($key in $($results.data[$i].data.sightings.docs[$j].relations.related | where-Object {$_.type -eq "email_subject"})){$key.value}
					$email_address = foreach($key in $($results.data[$i].data.sightings.docs[$j].relations.related | where-Object {$_.type -eq "email"})){$key.value}
					$outgoing_array = $($email_address | Get-Unique), $($($email_mid -split '-')[0] | Get-Unique), $($email_subject | Get-Unique)
					$Outgoing_list += ,$outgoing_array
				}
				if ($results.data[$i].data.sightings.docs[$j].description -match "Incoming"){
					$email_mid = foreach($key in $($results.data[$i].data.sightings.docs[$j].relations.related | where-Object {$_.type -eq "cisco_mid"})){$key.value}
					$email_subject = foreach($key in $($results.data[$i].data.sightings.docs[$j].relations.related | where-Object {$_.type -eq "email_subject"})){$key.value}
					$email_address = foreach($key in $($results.data[$i].data.sightings.docs[$j].relations.related | where-Object {$_.type -eq "email"})){$key.value}
					$incoming_array = $($email_address | Get-Unique), $($($email_mid -split '-')[0] | Get-Unique), $($email_subject | Get-Unique)
					$Incoming_list += ,$incoming_array
				}
			}
			Write-OutPut "Incoming Email List:" 
			Write-OutPut $Incoming_list | % { $_ -join ','} 
			Write-OutPut "--------------------------------------------------------------------" 
			Write-OutPut "Outgoing Email List:"
			Write-OutPut $Outgoing_list | % { $_ -join ','} 
			Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" 
		}
	}
}

	
$CONTENT = $Args[0]
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
SecureX-Investigation
