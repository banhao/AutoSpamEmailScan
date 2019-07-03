<#
.SYNOPSIS
  <>

.DESCRIPTION
  <>

.PARAMETER <Parameter_Name>
  <>

.INPUTS
  <>

.OUTPUTS
  <>

.NOTES
  Before start running the script, download the Exchange Web Services Managed API 2.2 and install it.
  https://www.microsoft.com/en-us/download/details.aspx?id=42951
  
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
	......
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
	......
	The trick is even someone can get the encoded string from the init.conf and use base64 to decode it, but they don't know the salt, so they still can't get the password.
  
  Version:        2.0
  Author:         <HAO BAN/hao.ban@ehealthsask.ca>
  Creation Date:  <07/03/2019>
  Purpose/Change: Resolve the issue that attachment is an Email.
  
.EXAMPLE
  This PowerShell passed the test in PowerShell version 5.1.16299.1146
  PS H:\>host  
	Check the PowerShell version.
 
#>
#-------------------------------------------------------------------------------------------------------------------------------------------------------
#variables
cls
$SALT = $Args[0]
$ENCODEDPASSWORD = Get-Content .\init.conf | findstr PASSWORD |  %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }

if ( [string]::IsNullOrEmpty($SALT) ){ 
	$YorN = Read-Host "The salt is empty. Do you want to input the sale to decrypt the password? [ y/n ] (Default is y)" 
	if ( $YorN -match "[yY]" -or ([string]::IsNullOrEmpty($YorN))){
		$SALT = Read-Host -assecurestring "Please input the salt"
		$PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SALT))),"")
	}else{ $PASSWORD = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD)) }
}else { $PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($SALT,"") }

$USERNAME = Get-Content .\init.conf | findstr USERNAME |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$DOMAIN = Get-Content .\init.conf | findstr DOMAIN |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EMAILADDRESS = Get-Content .\init.conf | findstr EMAILADDRESS |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EXCHANGESRV = Get-Content .\init.conf | findstr EXCHANGESRV |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$DLLPATH = Get-Content .\init.conf | findstr DLLPATH |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$DOWNLOADDIRECTORY =  Get-Content .\init.conf | findstr DOWNLOADDIRECTORY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$REPORTSDIRECTORY = Get-Content .\init.conf | findstr REPORTSDIRECTORY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EXTENSIONARRAY = Get-Content .\init.conf | findstr EXTENSIONARRAY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$EXEMPTURL = (Get-Content .\init.conf | findstr EXEMPTURL |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }).split(",")
$REPLYCC = Get-Content .\init.conf | findstr REPLYCC |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$SUBFOLDER = Get-Content .\init.conf | findstr SUBFOLDER | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$INTERVAL = [int]$(Get-Content .\init.conf | findstr INTERVAL | %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() })

$VIRUSTOTAL_API_KEY = Get-Content .\init.conf | findstr VIRUSTOTAL_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$URLSCAN_API_KEY = Get-Content .\init.conf | findstr URLSCAN_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$GOOGLE_API_KEY = Get-Content .\init.conf | findstr GOOGLE_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }

Import-Module $DLLPATH

$SERVICE = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2)
$SERVICE.Credentials = New-Object Net.NetworkCredential($USERNAME, $PASSWORD, $DOMAIN)
$SERVICE.AutodiscoverUrl($EMAILADDRESS)
$INBOX = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($SERVICE,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
$FOLDERID = ($INBOX.FindFolders([Microsoft.Exchange.WebServices.Data.FolderView]::new(10)) | where { $_.DisplayName -eq $SUBFOLDER }).Id.UniqueID
$PROPERTYSET = new-object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)
$PROPERTYSET.RequestedBodyType = [Microsoft.Exchange.WebServices.Data.BodyType]::Text

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

If(!(test-path $DOWNLOADDIRECTORY)){ New-Item -ItemType directory -Path $DOWNLOADDIRECTORY }
If(!(test-path $REPORTSDIRECTORY)){ New-Item -ItemType directory -Path $REPORTSDIRECTORY }



function Google-Safe-Browsing {
	$BODY = @()
	$BODY +=[pscustomobject]@{"client" = @{"clientId" = "Client ID"; "clientVersion" = "1.0"}; "threatInfo" = @{"threatTypes" = "MALWARE","SOCIAL_ENGINEERING"; "platformTypes" = "WINDOWS"; "threatEntryTypes" = "URL"; "threatEntries" = @{"url" = "$URL"}}}
	$HEADERS = @{ 'Content-Type' = "application/json" }
	$JSONBODY = $BODY | ConvertTo-Json
	$Uri = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+ $GOOGLE_API_KEY
	$Results = Invoke-RestMethod -Method 'POST' -Uri $Uri -Body $JSONBODY -Headers $HEADERS
	$ThreatType = $Results | ConvertFrom-Json | select -expand matches | select threatType
	Write-OutPut "Google Safe Browsing Report: " >> $LOGFILE
	if ( ([string]::IsNullOrEmpty($ThreatType)) ) { Write-OutPut "Can not find the result in Google Safe Browsing Scan."  >> $LOGFILE }else{ Write-OutPut "Google Safe Browsing Scan Results:    ",$($ThreatType) >> $LOGFILE }
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
}

function Submit-URLSCAN {
	$BODY = @{ 'url' = "$URL"; 'public' = 'on' }
	$HEADERS = @{ 'API-Key' = "$URLSCAN_API_KEY" }
	$SCANRESPONSE = Invoke-RestMethod -Method 'POST' -Uri 'https://urlscan.io/api/v1/scan/' -Headers $HEADERS -Body $BODY
	$RESPONSEAPI = $SCANRESPONSE.api
	Do {
		Start-Sleep -s 15
		$RESPONSE = try { $RESULTS = Invoke-RestMethod -Method 'GET' -Uri $RESPONSEAPI } catch { $_.Exception.Response.StatusCode.Value__}
    } Until ($RESPONSE -ne 404) 
	$ReportURL = $RESULTS.task.reportURL
	$ScreenShot = $RESULTS.task.screenshotURL
	Write-OutPut "urlscan.io Report: " >> $LOGFILE
	Write-OutPut "ScanReportURL:    ",$($ReportURL) >> $LOGFILE
	Write-OutPut "ScreenShotURL:    ",$($ScreenShot) >> $LOGFILE
	Start-Sleep -s 3
}

function Submit-URL-Virustotal {
	# submit URL
	$BODY = @{ "url" = "$URL"; "apikey" = "$VIRUSTOTAL_API_KEY" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/url/scan' -Body $BODY
	Start-Sleep -s 15
	# Get Report
	$RESOURCE = $SCAN.scan_id
	$BODY_RPT = @{ "resource" = "$RESOURCE"; "apikey" = "$VIRUSTOTAL_API_KEY" }
	$REPORT = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/url/report' -Body $BODY_RPT
	Write-OutPut "VirusTotal URL Scan Report: " >> $LOGFILE
	Write-OutPut $($REPORT.permalink) >> $LOGFILE
	Write-OutPut "POSITIVES |   TOTAL" >> $LOGFILE
	Write-OutPut $($REPORT.positives) "        |  " $($REPORT.total) >> $LOGFILE
}

function Submit-FILE-Virustotal {
	Do {
		# check the file report 
		$BODY_RPT = @{ "resource" = "$HASH"; "apikey" = "$VIRUSTOTAL_API_KEY" }
		$REPORT = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $BODY_RPT
		if ($REPORT.response_code -eq 0){
			# scan a file
			Start-Sleep -s 15
			$BODY = @{ "apikey" = "$VIRUSTOTAL_API_KEY"; "file" = "$FILEPATH" }
			$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/scan' -Body $BODY
			$HASH = $SCAN.sha256
		}
		Start-Sleep -s 15
	}Until ($REPORT.response_code -eq 1)
	Write-OutPut "VirusTotal File Scan Report: " >> $LOGFILE
	Write-OutPut $($REPORT.permalink) >> $LOGFILE
	Write-OutPut "POSITIVES |   TOTAL" >> $LOGFILE
	Write-OutPut $($REPORT.positives) "        |  " $($REPORT.total) >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
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
	$TextBody = $CdoMessage.Fields.Item("urn:schemas:httpmail:textdescription").Value
	$HTMLBody = $CdoMessage.Fields.Item("urn:schemas:httpmail:htmldescription").Value
	$EmailBODY = $TextBody + $HTMLBody
	$URLLIST = $EmailBODY | select-string -pattern $URLRegEx -AllMatches  | %{ $_.Matches } | %{ $_.Value } | Sort-Object | ? {$EXEMPTURL -notcontains $_} | Get-Unique
	$EXPLIST = $EXEMPTURL | foreach-object { $URLLIST -match $_ }
	$URLARRAY = @()
	foreach ($URL in $URLLIST){ if ( $URL -notin $EXPLIST ){$URLARRAY = $URLARRAY += $URL }}
	if ( -not ([string]::IsNullOrEmpty($URLARRAY)) ){
		foreach($URL in $URLARRAY){ 
			Write-OutPut "URL:     ",$URL  >> $LOGFILE
			Submit-URL-Virustotal
			Submit-URLSCAN
			Google-Safe-Browsing
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
			$ALGORITHM = (Get-FileHash ($ATTFILENAME)).Algorithm
			$HASH = (Get-FileHash ($ATTFILENAME)).Hash.ToLower()
			$FILEPATH = (Get-FileHash ($ATTFILENAME)).Path
			Write-OutPut "Attachment $ALGORITHM Hash : "  $HASH >> $LOGFILE
			if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){ Submit-FILE-Virustotal }
		}
	}
}

function ConvertLogToHTML {
	$File = Get-Content $LOGFILE
	$FileLine = @()
	Foreach ($Line in $File) {
		$MyObject = New-Object -TypeName PSObject
		if ( ($Line -match "virustotal.com") -or ($Line -match "urlscan.io") ){
			if ($Line -match ".png"){
				Add-Member -InputObject $MyObject -Type NoteProperty -Name "Security Scan Report" -Value "<a href='$Line'>$Line</a><img src='$Line' height='640' width='800'>"
			}else{ Add-Member -InputObject $MyObject -Type NoteProperty -Name "Security Scan Report" -Value "<a href='$Line'>$Line</a>" }
		}else{ Add-Member -InputObject $MyObject -Type NoteProperty -Name "Security Scan Report" -Value $Line }
		$FileLine += $MyObject
	}
	$($FileLine | ConvertTo-Html -Title "Security Scan Report" -Property "Security Scan Report" ) -replace '&gt;','>' -replace '&lt;','<' -replace '&#39;',"'" | Out-File $HTMLFILE
}

function MAIN {
date
$ITEMS = $INBOX.FindItems($INBOX.TotalCount)
foreach ( $EMAIL in $ITEMS.Items ){
	# only get unread emails
	if( $EMAIL.isread -eq $false ){
		# load the property set to get to the body
		$EMAIL.load($PROPERTYSET)
		$RANDOMID = -join ((48..57) + (97..122) | Get-Random -Count 20 | % {[char]$_})
		$LOGFILE = $REPORTSDIRECTORY+"security-scan-report_"+$RANDOMID+".log"
		$HTMLFILE = $REPORTSDIRECTORY+"security-scan-report_"+$RANDOMID+".html"
		#$EMAIL
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
				Submit-URL-Virustotal
				Submit-URLSCAN
				Google-Safe-Browsing
			} 
		}
		foreach($ATTACH in $EMAIL.Attachments){
			$EXTENSION = [System.IO.Path]::getExtension($ATTACH.Name.ToString().ToLower())
			# only save the file that extension is not in the extension list
			if ( !$EXTENSIONARRAY.contains($EXTENSION) -or [string]::IsNullOrEmpty($EXTENSION) ){
				if ( ($ATTACH.ContentType -eq "message/rfc822") -or ([string]::IsNullOrEmpty($ATTACH.ContentType)) -and ($ATTACH.PSobject.Properties.name -match "Item") ){
					Write-OutPut "=====================The attachment is an email=====================" >> $LOGFILE
					$MIMEPROPERTYSET = new-object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.ItemSchema]::MimeContent)
					$ATTACH.Load($MIMEPROPERTYSET)
					$AttachmentData = $ATTACH.Item.MimeContent.Content
					$ATTFILENAME = ($DOWNLOADDIRECTORY + [GUID]::NewGuid().ToString() + "_MSG.eml")
					$FileExtension = "eml"
				}else{
					$ATTACH.Load()
					$AttachmentData = $ATTACH.Content
					$ATTFILENAME = ($DOWNLOADDIRECTORY + $ATTACH.Name.ToString())
				}
				$ATTFILE = new-object System.IO.FileStream(($ATTFILENAME), [System.IO.FileMode]::Create)
				$ATTFILE.Write($AttachmentData, 0, $AttachmentData.Length)
				$ATTFILE.Close()
				Write-OutPut "Downloaded Attachment : "  ($ATTFILENAME) >> $LOGFILE
				$ALGORITHM = (Get-FileHash ($ATTFILENAME)).Algorithm
				$HASH = (Get-FileHash ($ATTFILENAME)).Hash.ToLower()
				$FILEPATH = (Get-FileHash ($ATTFILENAME)).Path
				Write-OutPut "Attachment $ALGORITHM Hash : "  $HASH >> $LOGFILE
				if ( $FileExtension -eq "eml" ){ 
					FromEmailAttachment $ATTFILENAME
					} else{				
						if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){ Submit-FILE-Virustotal }
					}
					
			}
		}
		Write-OutPut "=============================END====================================" >> $LOGFILE
		ConvertLogToHTML
		$REPLYTO = $($EMAIL.From.Address.ToString())
		$REPLYSUBJECT = "AUTO-REPLY/Security Scan Report-- "+$($EMAIL.Subject)
		Send-MailMessage -SmtpServer $EXCHANGESRV -To $REPLYTO -From $EMAILADDRESS -Cc $REPLYCC -Subject $REPLYSUBJECT -Body '<h4>Thanks for your email submission! Please view the Security Scan Report!</h4>' -BodyAsHtml -Attachments $HTMLFILE
	}
	$EMAIL.isRead = $true
	$EMAIL.Update([Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AutoResolve)
}
}

if ( $INTERVAL -eq 0 ){
	MAIN
}else{
	while($true){
		MAIN
		Start-Sleep -s $INTERVAL
	}
}
