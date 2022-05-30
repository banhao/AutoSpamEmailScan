<#PSScriptInfo

.VERSION 1.13

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR HAO BAN/hao.ban@ehealthsask.ca/banhao@gmail.com

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

.PRIVATEDATA

.SYNOPSIS

.EXAMPLE

.DESCRIPTION 
	Creation Date:  <05/30/2022>
	
.Parameter

#> 

#-------------------------------------------------------------------------------------------------------------------------------------------------------

[CmdletBinding(DefaultParameterSetName = "Indicator")]
Param(
	[Parameter(ParameterSetName="Indicator", Mandatory=$true, Position=0, HelpMessage="---Please input `"Indicator`" which support URL/domain/sha256/sha1/md5/IPv4/IPv6/email address---")] 
	[ValidateNotNullOrEmpty()]
	[string]$Indicator,
	
	[Parameter(ParameterSetName="Indicator", Mandatory=$true, Position=1, HelpMessage="---Please input Indicator `"Type`", only can be `"URL | domain | sha256 | sha1 | md5 | IPv4 | IPv6 | email-addr`"---")] 
	[ValidateNotNullOrEmpty()]
	[ValidateSet("URL", "domain", "sha256", "sha1", "md5", "IPv4", "IPv6", "email-addr")]
	[string]$Type,
	
	[Parameter(ParameterSetName="Indicator", Mandatory=$false, Position=2, HelpMessage="---Please input `"Expire`" Seconds---")] 
	[AllowEmptyCollection()]
	[int[]]$Expire,
	
	[Parameter(ParameterSetName="Indicator", Mandatory=$true, Position=3, HelpMessage="---Please input `"Comment`", if includes space please use double quote---")] 
	[AllowEmptyString()]
	[string]$Comment
)

If( $Indicator:paramMissing -or  $Type:paramMissing ){
	throw "---USAGE: MineMeld_Indicator.ps1 <Indicator> <URL | domain | sha256 | sha1 | md5 | IPv4 | IPv6 | email-addr> [Expire]---"
}

$MineMeldServer = Get-Content .\init.conf | findstr MineMeldServer |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$MineMeldNode = Get-Content .\init.conf | findstr MineMeldNode |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$MINEMELDCREDENTIAL = Get-Content .\init.conf | findstr MINEMELDCREDENTIAL |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$MineMeldApiUrl = $MineMeldServer + "/config/data/" + $MineMeldNode + "_indicators/append?h=" + $MineMeldNode + "&t=localdb"
$HEADERS = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$HEADERS.Add("Authorization", "Basic $MINEMELDCREDENTIAL")
$HEADERS.Add("Content-Type", "application/json")
if ( [string]::IsNullOrEmpty($Expire) ){ 
	[string]$Expire = "disabled"
	$BODY = "{ `n`"indicator`": `"$Indicator`", `n`"type`": `"$Type`", `n`"comment`": `"$Comment`", `n`"share_level`":  `"green`", `n`"confidence`": 100,  `n`"ttl`": `"$Expire`" `n}"
}else{
	$BODY = "{ `n`"indicator`": `"$Indicator`", `n`"type`": `"$Type`", `n`"comment`": `"$Comment`", `n`"share_level`":  `"green`", `n`"confidence`": 100,  `n`"ttl`": $Expire `n}"
	}
$BODY
Try { $MineMeldResponse = Invoke-RestMethod -Method 'POST' -Uri $MineMeldApiUrl -Headers $HEADERS -Body $BODY } Catch { $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream()) }
if ( [string]::IsNullOrEmpty($MineMeldResponse) ) {
	$reader.BaseStream.Position = 0
	$reader.DiscardBufferedData()
	if ( -not ([string]::IsNullOrEmpty($reader.ReadToEnd())) ) {
		Write-Output "Exception Error:" $reader.ReadToEnd()
	}
}else{ $MineMeldResponse | ConvertTo-Json }


if ( ($Type -eq "URL") -or ($Type -eq "domain") ){
	if ($Type -eq "URL"){
		$DstDomain = $([URI]$Indicator).host
		$DstURL = $Indicator
		
	}else{
		$DstDomain = $Indicator
		$DstURL = $Indicator
	}
	$Umbrella_API_Key = Get-Content .\init.conf | findstr Umbrella_API_Key |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
	$URL = "https://s-platform.api.opendns.com/1.0/events?customerKey=" + $Umbrella_API_Key
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Content-Type", "application/json")
	$DeviceID = ((get-itemproperty -path HKLM:\SOFTWARE\Microsoft\SQMClient -Name MachineID).MachineId).Trim("{","}")
	$DeviceVersion = "Windows"+$([environment]::OSVersion.Version.Major)+"/"+$([environment]::OSVersion.Version.Build)
	$ProviderName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -replace "\\", "-"
	$AlertTime = Get-Date -UFormat "%Y-%m-%dT%T%Z"
	if ( [string]::IsNullOrEmpty($Comment)){ 
		$ProtocolVersion = "1.0"
	}else{ $ProtocolVersion = $Comment }
	$body = "{`n    `"alertTime`": `"$AlertTime`",`n    `"deviceId`": `"$DeviceID`",`n    `"deviceVersion`": `"$DeviceVersion`",`n    `"dstDomain`": `"$DstDomain`",`n    `"dstUrl`": `"$DstURL`",`n    `"eventTime`": `"$AlertTime`",`n    `"protocolVersion`": `"$ProtocolVersion`",`n    `"providerName`": `"$ProviderName`"`n}"
	$response = Invoke-RestMethod $URL -Method 'POST' -Headers $headers -Body $body
	$response | ConvertTo-Json

	$URL = "https://s-platform.api.opendns.com/1.0/domains?customerKey=" + $Umbrella_API_Key
	$response = Invoke-RestMethod  $URL -Method 'GET' -Headers $headers
	$domain_list = @($response.data.name)
	while($true){
		if ($response.meta.next) {
			$URL = $response.meta.next
			$response = Invoke-RestMethod  $URL -Method 'GET' -Headers $headers
			$domain_list += @($response.data.name)
		}else{ break }
	}
	foreach ($domain in $domain_list) { 
		if ($domain -eq $DstDomain) { 
			Write-OutPut "$($domain) ia added into OpenDNS Block List successfully." 
			break
		}
	}
}


<#

#Delete
$body = ""
$URL = "https://s-platform.api.opendns.com/1.0/domains/" + $Indicator + "?customerKey=" + $Umbrella_API_Key
$response = Invoke-RestMethod $URL -Method 'DELETE' -Headers $headers -Body $body
$response | ConvertTo-Json

#>
