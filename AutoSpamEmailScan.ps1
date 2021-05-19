
<#PSScriptInfo

.VERSION 4.5.0

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR HAO BAN/banhao@gmail.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI https://github.com/banhao/AutoSpamEmailScan/blob/master/LICENSE

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES Before you run the script Install the Exchange Web Services Managed API 2.2. https://www.microsoft.com/en-us/download/details.aspx?id=42951 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
	
	Creation Date:  <05/19/2021>
	Purpose/Change: Add "BlockedMailSelfRelease" function. If you donnot have ESA/SMA or donott want to use ESA/SMA API to block SPAM sender or release blocked emails from quarantine then please setup "ENABLEESASPAMBL" and "ENABLESELFRELEASE" as "False" in init.conf  
	
	Creation Date:  <05/13/2021>
	Purpose/Change: Add "slblconfig EXPORT" after update the Cisco Email Security Appliance Spam Quarantine Blacklist.(related to Cisco Bug CSCvx12488)
	ssh PRIVATE KEY must be save in "c:\users\<username>\.ssh\" folder. ".ssh" folder must disable "inheritance" and manually grant "local\SYSTEM" group, "local\Administrators" group "full control" privilege, and current user "read only" privilege.

	Creation Date:  <04/05/2021>
	Purpose/Change: Optimize function CheckRedirectedURL{}

	Creation Date:  <03/25/2021>
	Purpose/Change: Update function CheckRedirectedURL{}

	Creation Date:  <03/19/2021>
	Purpose/Change: Add a new module for Cisco Email Security Appliance Spam Quarantine Blacklist.

	Creation Date:  <11/10/2020>
	Purpose/Change: Move emails to sub-folder when after the checking.

	Creation Date:  <04/03/2020>
	Purpose/Change: Optimize the parameters setting.

	Creation Date:  <04/02/2020>
	Purpose/Change: Add new feature to let the use input the credential just chose "N" when prompt "salt is empty". Add SystemException, fix the broken of the system error.

	Creation Date:  <03/10/2020>
	Purpose/Change: Add a new Function CheckRedirectedURL, this feature is used to detect URLs that try to escape the scan.
	Change "function Submit-URL-Virustotal" to use the VirusTotal API V3

	Creation Date:  <02/11/2020>
	Purpose/Change: Add checkphish.ai API limit error

	Creation Date:  <01/22/2020>
	Purpose/Change: Add a new Function checkphish.ai

	Creation Date:  <10/21/2019>
	Purpose/Change: One funcation name was changed but calls the old name in the program. Update the Bytescout.PDF2HTML.dll to version 10.6.0.3667. It's still a trial version and will expire after 90 days. If you see this error: 
	--------------------------------------------------------------------------------------
	"new-object : Exception calling ".ctor" with "0" argument(s): "Trial period expired."
	+         $extractor = new-object Bytescout.PDF2HTML.HTMLExtractor
	--------------------------------------------------------------------------------------
	That means the DLL file has been expired.

.PRIVATEDATA

.DESCRIPTION AutoSpamEmailScan.ps1 is used to monitor a specific mailbox that in enterprise users can forward suspicious spam emails to a specific mailbox.
	This PowerShell script can monitor the mailbox for any unread emails, grab the URLs and attachments from the emails and submit to virustotal.com, urlscan.io, Google safe browsing and OPSWAT. Script also can extract URLs from a pdf file.
	After the scan finished, script can generate HTML format scan report and auto reply to the senders.
	Script can be run once or loop interval, if  in the init.conf is 0 means script will only run one time else the number is the loop interval seconds.

	Visit https://github.com/banhao/AutoSpamEmailScan to get the init.conf and Bytescout.PDF2HTML.dll, this dll file is used to convert PDF to HTML.

	Please check the License before you download this script, if you don't agree with the License please don't download and use this script. https://github.com/banhao/AutoSpamEmailScan/blob/master/LICENSE

	The Password is base64 encoded and saved in init.conf, following is the example about how to genertae the encoded password:
	"JkPgsiG9Zh0XCvk" is the password.
	"yp9P7" is the salt. make sure salt is the unique string that can't have the same pattern in the password.
	Insert the salt into password where ever you want:
	yp9P7JkPgsiG9Zh0XCvk, JkPgsiG9Zh0XCvkyp9P7, JkPgyp9P7siG9Zh0XCvk, JkPgsiG9Zh0XCyp9P7vk, ...... all these are legitimate.
	
	Generate the base64 encoded string:
	[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("yp9P7JkPgsiG9Zh0XCvk"))
		eQBwADkAUAA3AEoAawBQAGcAcwBpAEcAOQBaAGgAMABYAEMAdgBrAA==
	[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("JkPgsiG9Zh0XCvkyp9P7"))
		SgBrAFAAZwBzAGkARwA5AFoAaAAwAFgAQwB2AGsAeQBwADkAUAA3AA==
	[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("JkPgyp9P7siG9Zh0XCvk"))
		SgBrAFAAZwB5AHAAOQBQADcAcwBpAEcAOQBaAGgAMABYAEMAdgBrAA==
	[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("JkPgsiG9Zh0XCyp9P7vk"))
		SgBrAFAAZwBzAGkARwA5AFoAaAAwAFgAQwB5AHAAOQBQADcAdgBrAA==
	
	Save the encoded string in the init.conf file.
	
	Decode the encoded string:
	[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("eQBwADkAUAA3AEoAawBQAGcAcwBpAEcAOQBaAGgAMABYAEMAdgBrAA=="))
		yp9P7JkPgsiG9Zh0XCvk
	[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("SgBrAFAAZwBzAGkARwA5AFoAaAAwAFgAQwB2AGsAeQBwADkAUAA3AA=="))
		JkPgsiG9Zh0XCvkyp9P7
	[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("SgBrAFAAZwB5AHAAOQBQADcAcwBpAEcAOQBaAGgAMABYAEMAdgBrAA=="))
		JkPgyp9P7siG9Zh0XCvk
	[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("SgBrAFAAZwBzAGkARwA5AFoAaAAwAFgAQwB5AHAAOQBQADcAdgBrAA=="))
		JkPgsiG9Zh0XCyp9P7vk
	
	Even someone can get the encoded string from the init.conf and use base64 to decode it, but they don't know the salt, so they still can't get the password directly.

	This PowerShell passed the test in PowerShell version 5.1.16299.1146. Can not run on Powershell version 4 and below.
	PS H:\>host  
	Check the PowerShell version.

#>


#-------------------------------------------------------------------------------------------------------------------------------------------------------
#variables
param ($CREDENTIAL,$SALT)
cls

if ( [string]::IsNullOrEmpty($CREDENTIAL) -and [string]::IsNullOrEmpty($SALT) ){
	$YorN = Read-Host "Do you want to input the Credential? [ y/n ] (Default is y)"
	if ( $YorN -match "[yY]" -or ([string]::IsNullOrEmpty($YorN))){
		$USERNAME = Get-Content .\init.conf | findstr USERNAME |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
		$CREDENTIAL = Get-Credential -credential $USERNAME
		$PASSWORD = $CREDENTIAL.Password
	}else{
		$ENCODEDPASSWORD = Get-Content .\init.conf | findstr PASSWORD |  %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
		$USERNAME = Get-Content .\init.conf | findstr USERNAME |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
		if ( [string]::IsNullOrEmpty($SALT) ){
			$YorN = Read-Host "The salt is empty. Do you want to input the salt to decrypt the password? [ y/n ] (Default is y)"
			if ( $YorN -match "[yY]" -or ([string]::IsNullOrEmpty($YorN))){
				$SALT = Read-Host -assecurestring "Please input the salt"
				$PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SALT))),"")
			}else{ $PASSWORD = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD)) }
		}else { $PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($SALT,"") }
	}
}else{
	$ENCODEDPASSWORD = Get-Content .\init.conf | findstr PASSWORD |  %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
	$USERNAME = Get-Content .\init.conf | findstr USERNAME |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
	if ( [string]::IsNullOrEmpty($SALT) ){
		$YorN = Read-Host "The salt is empty. Do you want to input the salt to decrypt the password? [ y/n ] (Default is y)"
		if ( $YorN -match "[yY]" -or ([string]::IsNullOrEmpty($YorN))){
			$SALT = Read-Host -assecurestring "Please input the salt"
			$PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SALT))),"")
		}else{ $PASSWORD = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD)) }
	}else { $PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($SALT,"") }
}
	
$DOMAIN = Get-Content .\init.conf | findstr DOMAIN |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EMAILADDRESS = Get-Content .\init.conf | findstr EMAILADDRESS |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EXCHANGESRV = Get-Content .\init.conf | findstr EXCHANGESRV |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EWSDLLPATH = Get-Content .\init.conf | findstr EWSDLLPATH |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$PDF2HTMLDLLPATH = Get-Content .\init.conf | findstr PDF2HTMLDLLPATH |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$DOWNLOADDIRECTORY =  Get-Content .\init.conf | findstr DOWNLOADDIRECTORY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$REPORTSDIRECTORY = Get-Content .\init.conf | findstr REPORTSDIRECTORY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EXTENSIONARRAY = Get-Content .\init.conf | findstr EXTENSIONARRAY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EXEMPTURL = (Get-Content .\init.conf | findstr EXEMPTURL |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }).split(",")
$SUBFOLDER = Get-Content .\init.conf | findstr SUBFOLDER | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$INTERVAL = [int]$(Get-Content .\init.conf | findstr INTERVAL | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() })
$ENABLEESASPAMBL  = $(Get-Content .\init.conf | findstr ENABLEESASPAMBL | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }).ToLower()
$ESAURL1 = Get-Content .\init.conf | findstr ESAURL1 | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$ESAURL2 = Get-Content .\init.conf | findstr ESAURL2 | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$PRIVATEKEY = Get-Content .\init.conf | findstr PRIVATEKEY | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$HOST1 = $([System.Uri]$ESAURL1).Host
$HOST2 = $([System.Uri]$ESAURL2).Host
$ENABLESELFRELEASE = $(Get-Content .\init.conf | findstr ENABLESELFRELEASE | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }).ToLower()
$SMAURL = Get-Content .\init.conf | findstr SMAURL | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$QUARANTINENAME = Get-Content .\init.conf | findstr QUARANTINENAME | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$SMA = $([System.Uri]$SMAURL).Host

$VIRUSTOTAL_API_KEY = Get-Content .\init.conf | findstr VIRUSTOTAL_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$URLSCAN_API_KEY = Get-Content .\init.conf | findstr URLSCAN_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$GOOGLE_API_KEY = Get-Content .\init.conf | findstr GOOGLE_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$OPSWAT_API_KEY = Get-Content .\init.conf | findstr OPSWAT_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$CHECKPHISH_API_KEY = Get-Content .\init.conf | findstr CHECKPHISH_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }

if ( $ENABLEESASPAMBL -eq "true" -or $ENABLESELFRELEASE -eq "true" ){
	$ESAUSERNAME = Read-Host "Please input the ESA/SMA Username"
	$ESAPASSWORD = Read-Host -assecurestring "Please input the Password"
	$ESACREDENTIAL = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($ESAUSERNAME+":"+$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ESAPASSWORD)))))
}

function Submit-CHECKPHISH {
	Write-OutPut "CheckPhish Scan Report: " >> $LOGFILE
	$HEADERS = @{ "Content-Type" = "application/json" }
	$SCANBODY = @{ "urlInfo" = @{ "url" = "$URL"} ; "apiKey" = "$CHECKPHISH_API_KEY" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://developers.checkphish.ai/api/neo/scan' -Headers $HEADERS -Body $(convertto-json($SCANBODY))
	if ( [string]::IsNullOrEmpty($SCAN.errorMessage) ) {
		Start-Sleep -s 60
		$RESULTBODY = @{ "apiKey" = "$CHECKPHISH_API_KEY" ; "jobID" = "$($SCAN.jobID)" ; "insights" = $true }
		$RESULTS = Invoke-RestMethod -Method 'POST' -Uri 'https://developers.checkphish.ai/api/neo/scan/status' -Headers $HEADERS -Body $(convertto-json($RESULTBODY))
		Write-OutPut "ScanResultsDisposition:    ",$($RESULTS.disposition) >> $LOGFILE
		Write-OutPut "ScanReportURL:             ",$($RESULTS.insights) >> $LOGFILE
		Write-OutPut "ScreenShotURL:             ",$($RESULTS.screenshot_path) >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}else {
		Write-OutPut $SCAN.errorMessage >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}
}

function Google-Safe-Browsing {
	Write-OutPut "Google Safe Browsing Scan Report: " >> $LOGFILE
	$BODY = @()
	$BODY +=[pscustomobject]@{"client" = @{"clientId" = "company"; "clientVersion" = "1.0"}; "threatInfo" = @{"threatTypes" = "MALWARE","SOCIAL_ENGINEERING"; "platformTypes" = "WINDOWS"; "threatEntryTypes" = "URL"; "threatEntries" = @{"url" = "$URL"}}}
	$HEADERS = @{ 'Content-Type' = "application/json" }
	$JSONBODY = $BODY | ConvertTo-Json
	$Uri = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+ $GOOGLE_API_KEY
	$Results = Invoke-RestMethod -Method 'POST' -Uri $Uri -Body $JSONBODY -Headers $HEADERS
	if ( ([string]::IsNullOrEmpty($Results)) ) {
		Write-OutPut "Can not find the result in Google Safe Browsing Scan."  >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	 }else{
		$ThreatType = $Results | select -expand matches | select threatType
		Write-OutPut "Google Safe Browsing Scan Results:    ",$($ThreatType) >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}
}

function Submit-URLSCAN {
	Write-OutPut "URLscan Scan Report: " >> $LOGFILE
	$BODY = @{ 'url' = "$URL"; 'public' = 'on' }
	$HEADERS = @{ 'API-Key' = "$URLSCAN_API_KEY" }
	Try { $SCANRESPONSE = Invoke-RestMethod -Method 'POST' -Uri 'https://urlscan.io/api/v1/scan/' -Headers $HEADERS -Body $BODY } Catch { $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream()) }
	if ( [string]::IsNullOrEmpty($SCANRESPONSE) ) {
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$Exception = $reader.ReadToEnd() | ConvertFrom-Json
	}
	if ( -not ([string]::IsNullOrEmpty($Exception)) ) {
		Write-Output "Exception Error:" $Exception.description >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}else{ 	
		$RESPONSEAPI = $SCANRESPONSE.api
		Do {
			Start-Sleep -s 30
			$RESPONSE = try { $SCANRESULT = Invoke-RestMethod -Method 'GET' -Uri $RESPONSEAPI } catch { $_.Exception.Response.StatusCode.Value__}
		}Until($RESPONSE -ne 404)
		$ReportURL = $SCANRESULT.task.reportURL
		$ScreenShot = $SCANRESULT.task.screenshotURL

		Write-OutPut "ScanReportURL:     ",$($ReportURL) >> $LOGFILE
		Write-OutPut "ScreenShotURL:     ",$($ScreenShot) >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
		Start-Sleep -s 3
	}
}

function Submit-URL-Virustotal {
	$BODY = @{ "url" = "$URL" }
	$HEADERS = @{ "x-apikey" = "$VIRUSTOTAL_API_KEY" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri "https://www.virustotal.com/api/v3/urls" -Headers $HEADERS -Body $BODY
	$RESULTID = $SCAN.data.id |  %{ $_.Split('-')[1]; } | foreach{ $_.ToString().Trim() }
	$PERMALINK = "https://virustotal.com/gui/url/"+$RESULTID+"/detection"
	Start-Sleep -s 30
	$SCANRESULTS = Invoke-RestMethod -Method 'GET' -Uri "https://www.virustotal.com/api/v3/urls/$RESULTID" -Headers $HEADERS
	Write-OutPut "VirusTotal URL Scan Report: " >> $LOGFILE
	Write-OutPut $PERMALINK >> $LOGFILE
	Write-OutPut "VirusTotal URL Scan Stats: " >> $LOGFILE
	Write-OutPut $SCANRESULTS.data.attributes.last_analysis_stats >> $LOGFILE
	Write-OutPut "VirusTotal URL COMMUNITY VOTES : " >> $LOGFILE
	Write-OutPut $SCANRESULTS.data.attributes.total_votes >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
}

function Submit-FILE-Virustotal {
	$BODY = @{ "apikey" = "$VIRUSTOTAL_API_KEY"; "file" = "$FILEPATH" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/scan' -Body $BODY
	$HASH = $SCAN.sha256
	Start-Sleep -s 60
	$HEADERS = @{ "x-apikey" = "$VIRUSTOTAL_API_KEY" }
	$SCAN = Invoke-RestMethod -Method 'GET' -Uri "https://www.virustotal.com/api/v3/files/$HASH" -Headers $HEADERS
	$PERMALINK = "https://virustotal.com/gui/file/"+$SCAN.data.id+"/detection"
	Write-OutPut "VirusTotal File Scan Report: " >> $LOGFILE
	Write-OutPut $PERMALINK >> $LOGFILE
	Write-OutPut "VirusTotal File Scan Stats: " >> $LOGFILE
	Write-OutPut $SCAN.data.attributes.last_analysis_stats >> $LOGFILE
	Write-OutPut "VirusTotal File COMMUNITY VOTES : " >> $LOGFILE
	Write-OutPut $SCAN.data.attributes.total_votes >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
}

function Submit-FILE-OPSWAT {
	$URI = 'https://api.metadefender.com/v4/hash/'+$HASH
	$HEADERS = @{}
	$HEADERS.Add('apikey', $OPSWAT_API_KEY)
	$RESPONSE = try { $SCANRESULT = Invoke-RestMethod -Method 'GET' -Uri $URI  -Headers $HEADERS } catch { $_.Exception.Response.StatusCode.Value__ }
	if ( $RESPONSE -eq 404){
		$FILENAME = Split-Path $FILEPATH -leaf
		$URI = 'https://api.metadefender.com/v4/file'
		$HEADERS = @{}
		$HEADERS.Add('apikey', $OPSWAT_API_KEY)
		$HEADERS.Add('filename', $FILENAME)
		$SCANRESULT = Invoke-RestMethod -Method 'Post' -Uri $URI  -Headers $HEADERS -Body $FILEPATH -ContentType 'application/octet-stream'
		$HASH = $SCANRESULT.sha256
		$DATA_ID = $SCANRESULT.data_id
		$URI = 'https://api.metadefender.com/v4/file/'+$DATA_ID
		$HEADERS = @{}
		$HEADERS.Add('apikey', $OPSWAT_API_KEY)
		Do {
			Start-Sleep -s 5
			$RESPONSE = try { $SCANRESULT = Invoke-RestMethod -Method 'GET' -Uri $URI -Headers $HEADERS } catch { $_.Exception.Response.StatusCode.Value__}
		} Until ($RESPONSE -ne 404) 
		Write-OutPut "OPSWAT MetaDefender Cloud File Scan Report: " >> $LOGFILE
		$RESULTLINK = 'https://metadefender.opswat.com/results#!/file/'+$HASH+'/hash/overview'
		Write-OutPut $RESULTLINK >> $LOGFILE
		Write-OutPut "POSITIVES |   TOTAL" >> $LOGFILE
		Write-OutPut $($SCANRESULT.scan_results.total_detected_avs) "        |  " $($SCANRESULT.scan_results.total_avs) >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}else {
		Write-OutPut "OPSWAT MetaDefender Cloud File Scan Report: " >> $LOGFILE
		$RESULTLINK = 'https://metadefender.opswat.com/results#!/file/'+$HASH+'/hash/overview'
		Write-OutPut $RESULTLINK >> $LOGFILE
		Write-OutPut "POSITIVES |   TOTAL" >> $LOGFILE
		Write-OutPut $($SCANRESULT.scan_results.total_detected_avs) "        |  " $($SCANRESULT.scan_results.total_avs) >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}
}

function FromEmailAttachment {
	$EMLData = Get-Content $Args[0]
	$AdoDbStream = New-Object -ComObject ADODB.Stream
	$AdoDbStream.Open()
	$AdoDbStream.LoadFromFile($Args[0])
	$CdoMessage = New-Object -ComObject CDO.Message
	$CdoMessage.DataSource.OpenObject($AdoDbStream,"_Stream")
	Write-OutPut "===From:    ",$($CdoMessage.From) >> $LOGFILE
	Write-OutPut "===To:    ",$($CdoMessage.To) >> $LOGFILE
	Write-OutPut "===Subject:    ",$($CdoMessage.Subject) >> $LOGFILE
	Write-OutPut "===DateTimeReceived:    ",$($CdoMessage.SentOn) >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	if ( $ENABLEESASPAMBL -eq "true"){
		if ( ($EMAIL.ToRecipients.Address -eq "blockforme@esa.company.com") -or ($EMAIL.ToRecipients.Address -eq "blockforall@esa.company.com")  ){
			ESASpamQuarantine
		}
	}
	if ( $ENABLESELFRELEASE -eq "true"){
		if ( ($EMAIL.ToRecipients.Address -eq "release@esa.company.com") ){
			BlockedMailSelfRelease
		}
	}
	if ( ($EMAIL.ToRecipients.Address -eq "investigation@esa.company.com") ){
		$INVESTIGATION = "true"
	}else{
		$INVESTIGATION = "false"
	}
	$TextBody = $CdoMessage.Fields.Item("urn:schemas:httpmail:textdescription").Value
	$HTMLBody = $CdoMessage.Fields.Item("urn:schemas:httpmail:htmldescription").Value
	$EmailBODY = $TextBody + $HTMLBody
	$URLLIST = $EmailBODY | select-string -pattern $URLRegEx -AllMatches  | %{ $_.Matches } | %{ $_.Value } | Sort-Object | ? {$EXEMPTURL -notcontains $_} | Get-Unique
	$EXPLIST = $EXEMPTURL | foreach-object { $URLLIST -match $_ }
	$URLARRAY = @()
	foreach ($URL in $URLLIST){ if ( $URL -notin $EXPLIST ){$URLARRAY = $URLARRAY += $URL }}
	if ( -not ([string]::IsNullOrEmpty($URLARRAY)) ){
		foreach($URL in $URLARRAY){
			Write-OutPut "URL:     ",$URL >> $LOGFILE
			Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
			CheckRedirectedURL
		}
	}
	$BOUNDARY = $CdoMessage.Fields.Item("urn:schemas:mailheader:content-type").Value | %{ $_.Split(';')[1]; } | %{ $_.Split('"')[1]; }
	for ($i=1;$i -le $CdoMessage.Attachments.count;$i++){
		$ContentMediaType = $CdoMessage.Attachments.Item($i).ContentMediaType
		$FILENAME = $CdoMessage.Attachments.Item($i).FileName
		$AttachmentPATTERN = """$FILENAME""(.*?)  --$BOUNDARY"
		$ATTACHDATA = [regex]::match($EMLData, $AttachmentPATTERN).Groups[1].Value
		if ( ($($ContentMediaType|%{$_.Split('/')[0];}) -eq "application") -and (-not [string]::IsNullOrEmpty($FILENAME))){
			$TRIMNUM = $ATTACHDATA.LastIndexOf("  ")+2
			$ATTACHMENTDATA = $ATTACHDATA.Remove(0,$TRIMNUM)
			$ATTFILENAME = ($DOWNLOADDIRECTORY + $FILENAME)
			$bytes = [Convert]::FromBase64String($ATTACHMENTDATA)
			[IO.File]::WriteAllBytes($ATTFILENAME, $bytes)
			Write-OutPut "Downloaded Attachment : "  ($ATTFILENAME) >> $LOGFILE
			Try { $ALGORITHM = (Get-FileHash ($ATTFILENAME)).Algorithm }
			Catch [System.SystemException] { $ExceptionError = $_.Exception.Message }
			if ( [string]::IsNullOrEmpty($ExceptionError) ) {
				$HASH = (Get-FileHash ($ATTFILENAME)).Hash.ToLower()
				$FILEPATH = (Get-FileHash ($ATTFILENAME)).Path
				Write-OutPut "Attachment $ALGORITHM Hash : "  $HASH >> $LOGFILE
				$EXTENSION = [System.IO.Path]::GetExtension($ATTFILENAME)
				if ( $EXTENSION -eq ".pdf" ){
					Write-OutPut "=====================Extract URLs from the PDF file=====================" >> $LOGFILE
					ExtractURLFromPDFHTML
				}else{
					if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){
						Submit-FILE-Virustotal
						Submit-FILE-OPSWAT
					}
					}
			} else {
				Write-OutPut "********************************************************************" > $LOGFILE
				Write-Output "Exception Error:" $ExceptionError >> $LOGFILE   
				Write-OutPut "********************************************************************" > $LOGFILE
				}
		}
	}
}

function ESASpamQuarantine {
	$regex = [regex]"\<(.*)\>"
	$Blocklist_Sender = $($regex.match($($CdoMessage.From)).Groups[1].value).ToLower()
	if ( ($EMAIL.ToRecipients.Address -eq "blockforall@esa.company.com") ){
		$Blocklist_recipient = $('.*@'+$regex.match($($CdoMessage.To)).Groups[1].value.split("@")[1]).ToLower()
		$Blocklist_recipient_domain = $('.*@'+$regex.match($($CdoMessage.To)).Groups[1].value.split("@")[1]).ToLower()

	}else{
		if ( ($EMAIL.ToRecipients.Address -eq "blockforme@esa.company.com") ){
			$Blocklist_recipient = $($regex.match($($CdoMessage.To)).Groups[1].value).ToLower()
			$Blocklist_recipient_domain = $('.*@'+$regex.match($($CdoMessage.To)).Groups[1].value.split("@")[1]).ToLower()
		}
	}
	$HEADERS = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$HEADERS.Add("Authorization", "Basic $ESACREDENTIAL")
	$HEADERS.Add("Content-Type", "text/plain")
	$SenderList = $(Invoke-RestMethod -Method 'GET' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist?action=view&quarantineType=spam&viewBy=recipient&search=$Blocklist_recipient" -Headers $HEADERS).data.senderList
	$SenderList_domain = $(Invoke-RestMethod -Method 'GET' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist?action=view&quarantineType=spam&viewBy=recipient&search=$Blocklist_recipient_domain" -Headers $HEADERS).data.senderList
	if ( ([string]::IsNullOrEmpty($SenderList)) -and ([string]::IsNullOrEmpty($SenderList_domain)) ){
		$BODY = "{ `n`"action`": `"add`", `n`"quarantineType`": `"spam`", `n`"viewBy`": `"recipient`", `n`"senderList`":  [`"$Blocklist_Sender`"], `n`"recipientAddresses`": [`"$Blocklist_recipient`"] `n}"
		$Response_1 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
		ssh -i ~\.ssh\$PRIVATEKEY $ESAUSERNAME@$HOST1 "slblconfig EXPORT"
		$Response_2 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL2/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
		ssh -i ~\.ssh\$PRIVATEKEY $ESAUSERNAME@$HOST2 "slblconfig EXPORT"
		Write-OutPut "********************************************************************" >> $LOGFILE
		Write-Output $Response_1 | ConvertTo-Json >> $LOGFILE
		Write-Output $Response_2 | ConvertTo-Json >> $LOGFILE
		Write-OutPut "********************************************************************" >> $LOGFILE
	}else{
		if ( ($Blocklist_Sender -in $SenderList) -or ($Blocklist_Sender -in $SenderList_domain) ){
			Write-OutPut "********************************************************************" >> $LOGFILE
			Write-OutPut "$Blocklist_Sender was already blocked in $Blocklist_recipient Blocklist." >> $LOGFILE
			Write-OutPut "********************************************************************" >> $LOGFILE
		}else{
			$BODY = "{ `n`"action`": `"append`", `n`"quarantineType`": `"spam`", `n`"viewBy`": `"sender`", `n`"senderAddresses`":  [`"$Blocklist_Sender`"], `n`"recipientList`": [`"$Blocklist_recipient`"] }"
			$Response_1 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL1/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
			$Response_2 = Invoke-RestMethod -Method 'POST' -Uri "$ESAURL2/esa/api/v2.0/quarantine/blocklist" -Headers $HEADERS -Body $BODY
			Write-OutPut "********************************************************************" >> $LOGFILE
			Write-OutPut "*************************Block the Sender***************************" >> $LOGFILE
			Write-OutPut "********************************************************************" >> $LOGFILE
			Write-Output $Response_1 | ConvertTo-Json >> $LOGFILE
			Write-Output $Response_2 | ConvertTo-Json >> $LOGFILE   
			Write-OutPut "********************************************************************" >> $LOGFILE
		}
	}
}


function BlockedMailSelfRelease {
	$regex = [regex]"Message ID\:.*"
	$Message_ID_ESA = $($regex.match($($CdoMessage.TextBody)).value) | %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }
	$SMA_MAIL_LOGS = ssh -i ~\.ssh\$PRIVATEKEY $ESAUSERNAME@$SMA "grep $Message_ID_ESA mail_logs" | findstr "MID"
	$regex_MID = [regex]"MID .* \("
	$Message_ID = $regex_MID.match($SMA_MAIL_LOGS).Value.split(" ")[1]
	$HEADERS = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$HEADERS.Add("Authorization", "Basic $ESACREDENTIAL")
	$HEADERS.Add("Content-Type", "text/plain")
	$BODY = "{ `n`"action`": `"release`", `n`"mids`": [$Message_ID], `n`"quarantineName`": `"$QUARANTINENAME`", `n`"quarantineType`": `"pvo`" `n}"
	$Response = Invoke-RestMethod -Method 'POST' -Uri "$SMAURL/sma/api/v2.0/quarantine/messages" -Headers $HEADERS -Body $BODY
	$SMTPSERVER = Get-Content .\init.conf | findstr SMTPSERVER |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
	$REPLYTO = $($EMAIL.From.Address.ToString())
	$EMAIBODY = 'Message Information:' + "`r`n" + 'Email From: ' + $($CdoMessage.From) + "`r`n" + 'Subject: ' + $($CdoMessage.Subject) + "`r`n" + 'Date: ' + $($CdoMessage.SentOn) + "`r`n" + 'Message ID: ' + $Message_ID_ESA
	if ( $Response.data.totalCount -eq 0 ){
		$REPLYSUBJECT = "AUTO-REPLY/Blocked Email not found OR released already--- "+$Message_ID_ESA
	}
	if ( $Response.data.totalCount -eq 1 ){
		$REPLYSUBJECT = "AUTO-REPLY/Blocked Email released successfully--- "+$Message_ID_ESA
	}
	Send-MailMessage -SmtpServer $SMTPSERVER -To $REPLYTO -From $EMAILADDRESS -Subject $REPLYSUBJECT -Body $EMAIBODY
	Write-OutPut "********************************************************************" >> $LOGFILE
	Write-OutPut "*****************Release Email From Quarantine**********************" >> $LOGFILE
	Write-OutPut "********************************************************************" >> $LOGFILE
	Write-Output $Response | ConvertTo-Json >> $LOGFILE
	Write-OutPut "********************************************************************" >> $LOGFILE
}


function ConvertLogToHTML {
	$File = Get-Content $LOGFILE
	$FileLine = @()
	Foreach ($Line in $File) {
		$MyObject = New-Object -TypeName PSObject
		if ( ($Line -match "virustotal.com") -or ($Line -match "urlscan.io") -or ($Line -match "opswat.com") -or ($Line -match "checkphish.ai") -or ($Line -match "googleapis.com") ){
			if ($Line -match ".png"){
				Add-Member -InputObject $MyObject -Type NoteProperty -Name "Security Scan Report" -Value "<a href='$Line'>$Line</a><img src='$Line' height='640' width='800'>"
			}else{ Add-Member -InputObject $MyObject -Type NoteProperty -Name "Security Scan Report" -Value "<a href='$Line'>$Line</a>" }
		}else{ Add-Member -InputObject $MyObject -Type NoteProperty -Name "Security Scan Report" -Value $Line }
		$FileLine += $MyObject
	}
	$($FileLine | ConvertTo-Html -Title "Security Scan Report" -Property "Security Scan Report" ) -replace '&gt;','>' -replace '&lt;','<' -replace '&#39;',"'" | Out-File $HTMLREPFILE
}

function ExtractURLFromPDFHTML {
	if ( $EXTENSION -eq ".pdf" ){
		Add-Type -Path $PDF2HTMLDLLPATH
		$extractor = new-object Bytescout.PDF2HTML.HTMLExtractor
		$extractor.CheckPermissions = $False
		$extractor.LoadDocumentFromFile($ATTFILENAME)
		$BaseName = gci $ATTFILENAME | %{$_.BaseName}
		$FilePath = Split-Path -path $ATTFILENAME
		$HTMLFILE = $FilePath+"\"+$BaseName+".html"
		$extractor.SaveHtmlToFile($HTMLFILE)
		$extractor.Reset()
	}else{
		$HTMLFILE = $ATTFILENAME
	}
		$URLArrayFromHTML = Get-Content $HTMLFILE | select-string -pattern $URLRegEx -AllMatches | %{ $_.Matches } | %{ $_.Value } | Sort-Object | Get-Unique
		$URLArrayFromPDF = Get-Content $ATTFILENAME | select-string -pattern $URLRegEx -AllMatches | %{ $_.Matches } | %{ $_.Value } | Sort-Object | Get-Unique
		$URLLIST = $URLArrayFromHTML + $URLArrayFromPDF | Sort-Object | Get-Unique
		$EXPLIST = $EXEMPTURL | foreach-object { $URLLIST -match $_ }
		$URLARRAY = @()
	foreach ($URL in $URLLIST){ if ( $URL -notin $EXPLIST ){$URLARRAY = $URLARRAY += $URL }}
	# URL is not null or empty do check the URL
	if ( -not ([string]::IsNullOrEmpty($URLARRAY)) ){
		foreach($URL in $URLARRAY){
			Write-OutPut "URL:     ",$URL >> $LOGFILE
			Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
			CheckRedirectedURL
			}
	}else{ Write-OutPut "=====================No URL in the PDF/HTML file needs to scan=====================" >> $LOGFILE }
}

function CheckRedirectedURL {
	Try { $webRequest = [System.Net.WebRequest]::Create($URL) } Catch { $ExceptionError = $_.Exception.Message }
	if ( [string]::IsNullOrEmpty($ExceptionError) ) {
		if ( [string]::IsNullOrEmpty($([URI]$URL).Scheme) ) { $URL = "http://"+$URL }
		$webRequest.AllowAutoRedirect=$false
		Try { $webResponse = $webRequest.GetResponse() } Catch { $ExceptionError = $_.Exception.Message }	
		
		if ( [string]::IsNullOrEmpty($ExceptionError) ) {
			if ( ($webResponse.StatusCode -eq "Found") -or ($webResponse.StatusCode -eq "Redirect") ) {
				Write-Output "The Original URL is:" $URL >> $LOGFILE
				$URL = $webResponse.GetResponseHeader("Location")	
				Write-OutPut "    |" >> $LOGFILE
				Write-Output "    |--> The Redirected URL is:" $URL >> $LOGFILE
				Submit-URL-Virustotal
				Submit-URLSCAN
				Submit-CHECKPHISH
				Google-Safe-Browsing
			}else{
				if ( $webResponse.ResponseUri.OriginalString -eq $webResponse.ResponseUri.AbsoluteUri )  {
					Write-Output "No Redirection, Will scan the Original URL" >> $LOGFILE
					Submit-URL-Virustotal
					Submit-URLSCAN
					Submit-CHECKPHISH
					Google-Safe-Browsing
				}
			}
		}else{
			Write-Output "Exception Error:" $ExceptionError >> $LOGFILE
			Write-Output "Will scan the Original URL" >> $LOGFILE
			Submit-URL-Virustotal
			Submit-URLSCAN
			Submit-CHECKPHISH
			Google-Safe-Browsing	
		}
		Get-Job | Wait-Job
		$webResponse.Close()
	}else { 
		Write-Output "Exception Error:" $ExceptionError >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
		}
}

function MAIN {
	date
	If(!(test-path $DOWNLOADDIRECTORY)){ New-Item -ItemType directory -Path $DOWNLOADDIRECTORY }
	If(!(test-path $REPORTSDIRECTORY)){ New-Item -ItemType directory -Path $REPORTSDIRECTORY }
	Import-Module $EWSDLLPATH
	$SERVICE = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2)
	$SERVICE.Credentials = New-Object Net.NetworkCredential($USERNAME, $PASSWORD, $DOMAIN)
	$SERVICE.AutodiscoverUrl($EMAILADDRESS)
	$INBOX = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($SERVICE,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
	$FOLDERROOT = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($SERVICE,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::msgFolderRoot)
	$SUBFOLDERID = ($FOLDERROOT.FindFolders([Microsoft.Exchange.WebServices.Data.FolderView]100) | where { $_.DisplayName -eq $SUBFOLDER }).Id
	$PROPERTYSET = new-object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)
	$PROPERTYSET.RequestedBodyType = [Microsoft.Exchange.WebServices.Data.BodyType]::Text
	[System.Net.ServicePointManager]::SecurityProtocol = @("Tls12","Tls11","Tls","Ssl3")
#	Use .Net Object to ignore self-signed certificate
	if ("TrustAllCertsPolicy" -as [type]) {}
	else {
	Add-Type @"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
			return true;
		}
	}
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	}
	if ( $INBOX.TotalCount -ne 0 ){
		$ITEMS = $INBOX.FindItems($INBOX.TotalCount)
		foreach ( $EMAIL in $ITEMS.Items ){
			# only get unread emails
			if( $EMAIL.isread -eq $false ){
					# load the property set to get to the body
					$EMAIL.load($PROPERTYSET)
					$RANDOMID = -join ((48..57) + (97..122) | Get-Random -Count 20 | % {[char]$_})
					$LOGFILE = $REPORTSDIRECTORY+"security-scan-report_"+$RANDOMID+".log"
					$HTMLREPFILE = $REPORTSDIRECTORY+"security-scan-report_"+$RANDOMID+".html"
					# output the results - first of all the From, Subject and Date Time Received
					Write-OutPut "====================================================================" > $LOGFILE
					Write-OutPut "From:    ",$($EMAIL.From) >> $LOGFILE
					Write-OutPut "To:    ",$($EMAIL.ToRecipients) >> $LOGFILE
					Write-OutPut "Subject: ",$($EMAIL.Subject) >> $LOGFILE
					Write-OutPut "DateTimeReceived:    ",$($EMAIL.DateTimeReceived) >> $LOGFILE
					Write-OutPut "===================================================================="  >> $LOGFILE
					$URLRegEx = '\b(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[A-Z0-9+&@#/%=~_|$])'
					$URLLIST = $($EMAIL.Body.Text) | select-string -pattern $URLRegEx -AllMatches | %{ $_.Matches } | %{ $_.Value } | Sort-Object | Get-Unique
					$EXPLIST = $EXEMPTURL | foreach-object { $URLLIST -match $_ }
					$URLARRAY = @()
					foreach ($URL in $URLLIST){ if ( $URL -notin $EXPLIST ){$URLARRAY = $URLARRAY += $URL }}
					# URL is not null or empty do check the URL
					if ( -not ([string]::IsNullOrEmpty($URLARRAY)) ){
						foreach($URL in $URLARRAY){
							Write-OutPut "URL:     ",$URL >> $LOGFILE
							Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
							CheckRedirectedURL
						}
					}
					foreach($ATTACH in $EMAIL.Attachments){
						if ( ![string]::IsNullOrEmpty($ATTACH.Name)){
							$EXTENSION = [System.IO.Path]::GetExtension($ATTACH.Name.ToString().ToLower())
							}else{ $EXTENSION ="" }
						# only save the file that extension is not in the extension list
						if ( !$EXTENSIONARRAY.contains($EXTENSION) -or [string]::IsNullOrEmpty($EXTENSION) ){
							if ( ($ATTACH.ContentType -eq "message/rfc822") -or ([string]::IsNullOrEmpty($ATTACH.ContentType)) -and ($ATTACH.PSobject.Properties.name -match "Item") ){
								Write-OutPut "=====================The attachment is an email=====================" >> $LOGFILE
								$MIMEPROPERTYSET = new-object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.ItemSchema]::MimeContent)
								$ATTACH.Load($MIMEPROPERTYSET)
								$AttachmentData = $ATTACH.Item.MimeContent.Content
								$ATTFILENAME = ($DOWNLOADDIRECTORY + [GUID]::NewGuid().ToString() + "_MSG.eml")
								$EXTENSION = ".eml"
							}else{
								$ATTACH.Load()
								$AttachmentData = $ATTACH.Content
								$ATTFILENAME = ($DOWNLOADDIRECTORY + $ATTACH.Name.ToString().Trim(""))
							}
							Try { $ATTFILE = new-object System.IO.FileStream(($ATTFILENAME), [System.IO.FileMode]::Create) }
							Catch [System.SystemException] { $ExceptionError = $_.Exception.Message }
							if ( [string]::IsNullOrEmpty($ExceptionError) ) {
								$ATTFILE.Write($AttachmentData, 0, $AttachmentData.Length)
								$ATTFILE.Close()
								Write-OutPut "Downloaded Attachment : "  ($ATTFILENAME) >> $LOGFILE
								Try { $ALGORITHM = (Get-FileHash ($ATTFILENAME)).Algorithm }
								Catch [System.SystemException] { $ExceptionError = $_.Exception.Message }
								if ( [string]::IsNullOrEmpty($ExceptionError) ) {
									$HASH = (Get-FileHash ($ATTFILENAME)).Hash.ToLower()
									$FILEPATH = (Get-FileHash ($ATTFILENAME)).Path
									Write-OutPut "Attachment $ALGORITHM Hash : "  $HASH >> $LOGFILE
									if ( ($EXTENSION -eq ".eml") -or ($EXTENSION -eq ".raw") ){
										FromEmailAttachment $ATTFILENAME
									} else{
											if ( ($EXTENSION -eq ".pdf") -or ($EXTENSION -eq ".htm") -or ($EXTENSION -eq ".html") ){
												Write-OutPut "=====================Extract URLs from the PDF/HTML file=====================" >> $LOGFILE
												ExtractURLFromPDFHTML
												Submit-FILE-Virustotal
												Submit-FILE-OPSWAT
											}else {
												if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){
													Submit-FILE-Virustotal
													Submit-FILE-OPSWAT
												}
												}
										}
								} else {
									Write-OutPut "********************************************************************" > $LOGFILE
									Write-Output "Exception Error:" $ExceptionError >> $LOGFILE   
									Write-OutPut "********************************************************************" > $LOGFILE
									}
							} else {
									Write-OutPut "********************************************************************" > $LOGFILE
									Write-Output "Exception Error:" $ExceptionError >> $LOGFILE   
									Write-OutPut "********************************************************************" > $LOGFILE
								}		
						}
					}
					Write-OutPut "================================END=================================" >> $LOGFILE
					ConvertLogToHTML
					$REPLYSUBJECT = "AUTO-REPLY/Security Scan Report-- "+$($EMAIL.Subject)
					$SMTPSERVER = Get-Content .\init.conf | findstr SMTPSERVER |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					if ( $INVESTIGATION -eq "true" ) {
						$REPLYTO = $($EMAIL.From.Address.ToString())
					}else{
						$REPLYTO = Get-Content .\init.conf | findstr REPLYTO |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					}
					$REPLYCC = Get-Content .\init.conf | findstr REPLYCC |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					$EMAIBODY = '%CUSTOMER_EMAIL=' + $($EMAIL.From.Address) + "`r`n" + '%CUSTOMER=' + $($EMAIL.From.Name) + "`r`n" + '%SUMMARY=Security Scan Report--' + $($EMAIL.Subject)
					Send-MailMessage -SmtpServer $SMTPSERVER -To $REPLYTO -From $EMAILADDRESS -Cc $REPLYCC -Subject $REPLYSUBJECT -Body $EMAIBODY -Attachments $HTMLREPFILE
			}
			$EMAIL.isRead = $true
			$EMAIL.Update([Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AutoResolve)
			$EMAIL.Move($SUBFOLDERID)
		}
	}else{ Write-OutPut "==============There is no email in the inbox==================" }
}

# Main Procedure
if ( $INTERVAL -eq 0 ){
	MAIN
}else{
	while($true){
		MAIN
		Write-Host -NoNewline "==============After"$INTERVAL" seconds will check again=============="
		""
		Start-Sleep -s $INTERVAL
	}
}
