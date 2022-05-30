
<#PSScriptInfo

.VERSION 1.2

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR HAO BAN/banhao@gmail.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI https://github.com/banhao/ESA_SPAM_QUARANTINE_BLOCKLIST/blob/main/LICENSE

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
	Creation Date:  <01/24/2022>

.PRIVATEDATA

.SYNOPSIS

.EXAMPLE

.DESCRIPTION ESA_SPAM_QUARANTINE_BLOCKLIST.ps1 is used to add "email address" or "domain name" into ESA SPAM QUARANTINE BLOCKLIST by calling the ESA API.
	ESA_SPAM_QUARANTINE_BLOCKLIST.ps1 [-Sender] <string> [[-Recipient] <String>]

#>

#-------------------------------------------------------------------------------------------------------------------------------------------------------

[CmdletBinding(DefaultParameterSetName = "Indicator")]
Param(
	[Parameter(ParameterSetName="Indicator", Mandatory=$true, Position=0, HelpMessage="---`"Sender`" is mandatory, please input an email address or a domain name(e.g.: user@domain.com, server.domain.com, domain.com)---")] 
	[ValidateNotNullOrEmpty()]
	[string]$Sender,

	[Parameter(ParameterSetName="Indicator", Mandatory=$false, Position=1, HelpMessage="---Please input `"Recipient`" which can be an email address or a domain name---")] 
	[string]$Recipient
)


function ValidateEmailorDomain($arg) {
	($arg -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$") -or ($arg -match "^\w+([-+.']\w+)*\w+([-.]\w+)*\.\w+([-.]\w+)*$")
}

function ValidateEmail($arg) {
	$arg -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$" 
}

function ValidateDomain($arg) {
	$arg -match "^\w+([-+.']\w+)*\w+([-.]\w+)*\.\w+([-.]\w+)*$"
}

function ESASpamQuarantine($Block_Sender, $Block_Recipient) {
	if ( $(ValidateDomain($Block_Recipient)) ) {
		$Recipient_domain = '.*@'+$($Block_Recipient.split('@')[1])
	}else{
		$Recipient_domain = $Block_Recipient
	}

	$HEADERS = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$HEADERS.Add("Authorization", "Basic $ESACREDENTIAL")
	$HEADERS.Add("Content-Type", "text/plain")
	$SenderList = $(Invoke-RestMethod -Method 'GET' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist?action=view&quarantineType=spam&viewBy=recipient&search=$Block_Recipient" -Headers $HEADERS).data.senderList
	$SenderList_domain = $(Invoke-RestMethod -Method 'GET' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist?action=view&quarantineType=spam&viewBy=recipient&search=$Recipient_domain" -Headers $HEADERS).data.senderList
	if ( ([string]::IsNullOrEmpty($SenderList)) -and ([string]::IsNullOrEmpty($SenderList_domain)) ){
		$BODY = "{ `n`"action`": `"add`", `n`"quarantineType`": `"spam`", `n`"viewBy`": `"recipient`", `n`"senderList`":  [`"$Block_Sender`"], `n`"recipientAddresses`": [`"$Block_Recipient`"] `n}"
		$Response_1 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
		$Response_2 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL2/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
		Write-OutPut "********************************************************************"
		Write-Output $Response_1 | ConvertTo-Json
		Write-Output $Response_2 | ConvertTo-Json
		Write-OutPut "********************************************************************"
	}else{
		if ( ($Block_Sender -in $SenderList) -or ($Block_Sender -in $SenderList_domain) ){
			Write-OutPut "********************************************************************"
			Write-OutPut "$Block_Sender was already blocked in $Block_Recipient Blocklist."
			Write-OutPut "********************************************************************"
		}else{
			$BODY = "{ `n`"action`": `"append`", `n`"quarantineType`": `"spam`", `n`"viewBy`": `"sender`", `n`"senderAddresses`":  [`"$Block_Sender`"], `n`"recipientList`": [`"$Block_Recipient`"] }"
			$Response_1 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
			$Response_2 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL2/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
			Write-OutPut "********************************************************************"
			Write-OutPut "*************************Block the Sender***************************"
			Write-OutPut "********************************************************************"
			Write-Output $Response_1 | ConvertTo-Json
			Write-Output $Response_2 | ConvertTo-Json
			Write-OutPut "********************************************************************"
		}
	}
}

$ESAUSERNAME = Get-Content .\init.conf | findstr ESAUSERNAME |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$ESACREDENTIAL = Get-Content .\init.conf | findstr ESACREDENTIAL |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$ESAURL1 = Get-Content .\init.conf | findstr ESAURL1 |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$ESAURL2 = Get-Content .\init.conf | findstr ESAURL2 |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$HOST1 = $([System.Uri]$ESAURL1).Host
$HOST2 = $([System.Uri]$ESAURL2).Host
$PRIVATEKEY = Get-Content .\init.conf | findstr PRIVATEKEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }

if ( (-not [string]::IsNullOrEmpty($Sender)) -and (ValidateEmailorDomain($Sender)) ){
	$regex = [regex]".*\..*"
	$RAT_DomainList = $(ssh -i ~/.ssh/id_rsa_esa $ESAUSERNAME@$HOST1 "clustermode cluster; listenerconfig EDIT InboundMail RCPTACCESS PRINT" | %{ $_.Split(' ')[0];} | %{ $regex.match($_) }).value | Where-Object {$_}
	
	if ( [string]::IsNullOrEmpty($Recipient)){ 
		$i = 1
		$menu = @{}
		Write-Host "0. ALL"
		$menu.Add(0, "ALL")
		foreach($line in $RAT_DomainList) {
			Write-Host "$i. $line"
			$menu.Add($i, ($line))
			$i++
			}
		[int]$ans = Read-Host "Please select the Domain from the `"Recipient Access Table`" that you want to block for  [ 0 - $($i-1) ]"
		$selection = $menu.Item($ans)
		if ( ([string]::IsNullOrEmpty($selection)) ){
			write-output "------------------------------------------------------------------------------------------------------"
			Write-Output "Selection Wrong, Please correct it and try again."
		}else { 
			if ($selection -eq "ALL"){
				foreach($line in $RAT_DomainList) {
					ESASpamQuarantine $Sender.tolower() $('.*@'+$line).tolower()
				}
			}else {	
				ESASpamQuarantine $Sender.tolower() $('.*@'+$selection).tolower()
			}
		}
	}else{
		if ($Recipient -eq "ALL"){
			foreach($line in $RAT_DomainList) {
				ESASpamQuarantine $Sender.tolower() $('.*@'+$line).tolower()
			}
		}else { 
			if ( ValidateEmail($Recipient) ){
				ESASpamQuarantine $Sender.tolower() $Recipient.tolower()
			}else{ 
				if ( (ValidateDomain($Recipient)) -and ($Recipient -in $RAT_DomainList) ){
					ESASpamQuarantine $Sender.tolower() $('.*@'+$Recipient).tolower()
				}else{ Write-OutPut( "$Recipient is not valid, it only can be an email address or a domain name (e.g.: user@domain.com, server.domain.com, domain.com)") }
			}
		}
	}
	ssh -i ~\.ssh\$PRIVATEKEY $ESAUSERNAME@$HOST1 "slblconfig EXPORT"
	ssh -i ~\.ssh\$PRIVATEKEY $ESAUSERNAME@$HOST2 "slblconfig EXPORT"
}else{ Write-OutPut( "$Sender is not valid, it only can be an email address or a domain name (e.g.: user@domain.com, server.domain.com, domain.com)") }
