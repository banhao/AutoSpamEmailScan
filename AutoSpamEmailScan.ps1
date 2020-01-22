
<#PSScriptInfo

.VERSION 4.1.0

.GUID 134de175-8fd8-4938-9812-053ba39eed83

.AUTHOR banhao@gmail.com

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI https://github.com/banhao/AutoSpamEmailScan/blob/master/LICENSE

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#> 







<# 

.DESCRIPTION 
AutoSpamEmailScan.ps1 is used to monitor a specific mailbox that in enterprise users can forward suspicious spam emails to a specific mailbox. 
This PowerShell script can monitor the mailbox for any unread emails, grab the URLs and attachments from the emails and submit to virustotal.com, urlscan.io, Google safe browsing and OPSWAT. Script also can extract URLs from a pdf file. 
After the scan finished, script can generate HTML format scan report and auto reply to the senders.
Script can be run once or loop interval, if  in the init.conf is 0 means script will only run one time else the number is the loop interval seconds.

Before you run the script Install the Exchange Web Services Managed API 2.2. 
https://www.microsoft.com/en-us/download/details.aspx?id=42951 

Visit https://github.com/banhao/AutoSpamEmailScan to get the init.conf and Bytescout.PDF2HTML.dll, this dll file is used to convert PDF to HTML.

Please check the License before you download this script, if you don't agree with the License please don't download and use this script. https://github.com/banhao/AutoSpamEmailScan/blob/master/LICENSE

Update the Bytescout.PDF2HTML.dll to version 10.6.0.3667. It's still a trial version and will expire after 90 days. If you see this error: 
  --------------------------------------------------------------------------------------
  "new-object : Exception calling ".ctor" with "0" argument(s): "Trial period expired."
  At H:\MonitorEmailSecurity\MonitorEmailSecurity.ps1:273 char:16
  +         $extractor = new-object Bytescout.PDF2HTML.HTMLExtractor
  --------------------------------------------------------------------------------------
That means the DLL file has been expired.

#> 

Param()


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
  
  Version:        4.1.0
  Author:         <HAO BAN/banhao@gmail.com>

  Creation Date:  <01/22/2020>
  Purpose/Change: Add a new Function checkphish.ai

  Creation Date:  <10/21/2019>
  Purpose/Change: One funcation name was changed but calls the old name in the program. Update the Bytescout.PDF2HTML.dll to version 10.6.0.3667. It's still a trial version and will expire after 90 days. If you see this error: 
  --------------------------------------------------------------------------------------
  "new-object : Exception calling ".ctor" with "0" argument(s): "Trial period expired."
  At H:\MonitorEmailSecurity\MonitorEmailSecurity.ps1:273 char:16
  +         $extractor = new-object Bytescout.PDF2HTML.HTMLExtractor
  --------------------------------------------------------------------------------------
  That means the DLL file has been expired.
  
.EXAMPLE
  This PowerShell passed the test in PowerShell version 5.1.16299.1146. Can not run on Powershell version 4 and below.
  PS H:\>host  
	Check the PowerShell version.
 
#>
#-------------------------------------------------------------------------------------------------------------------------------------------------------
#variables
cls
$SALT = $Args[0]
$ENCODEDPASSWORD = Get-Content .\init.conf | findstr PASSWORD |  %{ $_.Split(':')[1]; } | foreach{ $_.ToString().Trim() }

if ( [string]::IsNullOrEmpty($SALT) ){ 
	$YorN = Read-Host "The salt is empty. Do you want to input the salt to decrypt the password? [ y/n ] (Default is y)" 
	if ( $YorN -match "[yY]" -or ([string]::IsNullOrEmpty($YorN))){
		$SALT = Read-Host -assecurestring "Please input the salt"
		$PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SALT))),"")
	}else{ $PASSWORD = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD)) }
}else { $PASSWORD = ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($ENCODEDPASSWORD))).Replace($SALT,"") }

$USERNAME = Get-Content .\init.conf | findstr USERNAME |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
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

$VIRUSTOTAL_API_KEY = Get-Content .\init.conf | findstr VIRUSTOTAL_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$URLSCAN_API_KEY = Get-Content .\init.conf | findstr URLSCAN_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$GOOGLE_API_KEY = Get-Content .\init.conf | findstr GOOGLE_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$OPSWAT_API_KEY = Get-Content .\init.conf | findstr OPSWAT_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
$CHECKPHISH_API_KEY = Get-Content .\init.conf | findstr CHECKPHISH_API_KEY |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }

function Submit-CHECKPHISH {
	$HEADERS = @{ "Content-Type" = "application/json" }
	$SCANBODY = @{ "urlInfo" = @{ "url" = "$URL"} ; "apiKey" = "$CHECKPHISH_API_KEY" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://developers.checkphish.ai/api/neo/scan' -Headers $HEADERS -Body $(convertto-json($SCANBODY))
	Start-Sleep -s 60
	$RESULTBODY = @{ "apiKey" = "$CHECKPHISH_API_KEY" ; "jobID" = "$($SCAN.jobID)" ; "insights" = $true }
	$RESULTS = Invoke-RestMethod -Method 'POST' -Uri 'https://developers.checkphish.ai/api/neo/scan/status' -Headers $HEADERS -Body $(convertto-json($RESULTBODY))
	Write-OutPut "CheckPhish Scan Report: " >> $LOGFILE
	Write-OutPut "ScanResultsDisposition:    ",$($RESULTS.disposition) >> $LOGFILE
	Write-OutPut "ScanReportURL:             ",$($RESULTS.insights) >> $LOGFILE
	Write-OutPut "ScreenShotURL:             ",$($RESULTS.screenshot_path) >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
}

function Google-Safe-Browsing {
	$BODY = @()
	$BODY +=[pscustomobject]@{"client" = @{"clientId" = "company"; "clientVersion" = "1.0"}; "threatInfo" = @{"threatTypes" = "MALWARE","SOCIAL_ENGINEERING"; "platformTypes" = "WINDOWS"; "threatEntryTypes" = "URL"; "threatEntries" = @{"url" = "$URL"}}}
	$HEADERS = @{ 'Content-Type' = "application/json" }
	$JSONBODY = $BODY | ConvertTo-Json
	$Uri = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+ $GOOGLE_API_KEY
	$Results = Invoke-RestMethod -Method 'POST' -Uri $Uri -Body $JSONBODY -Headers $HEADERS
	if ( ([string]::IsNullOrEmpty($Results)) ) { Write-OutPut "Can not find the result in Google Safe Browsing Scan."  >> $LOGFILE }else{
		$ThreatType = $Results | select -expand matches | select threatType
		Write-OutPut "Google Safe Browsing Report: " >> $LOGFILE
		Write-OutPut "Google Safe Browsing Scan Results:    ",$($ThreatType) >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}
}

function Submit-URLSCAN {
	$BODY = @{ 'url' = "$URL"; 'public' = 'on' }
	$HEADERS = @{ 'API-Key' = "$URLSCAN_API_KEY" }
	$SCANRESPONSE = Invoke-RestMethod -Method 'POST' -Uri 'https://urlscan.io/api/v1/scan/' -Headers $HEADERS -Body $BODY
	$RESPONSEAPI = $SCANRESPONSE.api
	Do {
		Start-Sleep -s 15
		$RESPONSE = try { $SCANRESULT = Invoke-RestMethod -Method 'GET' -Uri $RESPONSEAPI } catch { $_.Exception.Response.StatusCode.Value__}
    } Until ($RESPONSE -ne 404) 
	$ReportURL = $SCANRESULT.task.reportURL
	$ScreenShot = $SCANRESULT.task.screenshotURL
	Write-OutPut "URLscan Scan Report: " >> $LOGFILE
	Write-OutPut "ScanReportURL:     ",$($ReportURL) >> $LOGFILE
	Write-OutPut "ScreenShotURL:     ",$($ScreenShot) >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	Start-Sleep -s 3
}

function Submit-URL-Virustotal {
	$BODY = @{ "url" = "$URL"; "apikey" = "$VIRUSTOTAL_API_KEY" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/url/scan' -Body $BODY
	Start-Sleep -s 15
	$HEADERS = @{ "x-apikey" = "$VIRUSTOTAL_API_KEY" }
	$BASE64URL = ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$URL"))).replace('/','_').replace('=','')
	$SCAN = Invoke-RestMethod -Method 'GET' -Uri "https://www.virustotal.com/api/v3/urls/$BASE64URL" -Headers $HEADERS
	$PERMALINK = "https://virustotal.com/gui/url/"+$SCAN.data.id+"/detection"
	Write-OutPut "VirusTotal URL Scan Report: " >> $LOGFILE
	Write-OutPut $PERMALINK >> $LOGFILE
	Write-OutPut "VirusTotal URL Scan Stats: " >> $LOGFILE
	Write-OutPut $SCAN.data.attributes.last_analysis_stats >> $LOGFILE
	Write-OutPut "VirusTotal URL COMMUNITY VOTES : " >> $LOGFILE
	Write-OutPut $SCAN.data.attributes.total_votes >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
}

function Submit-FILE-Virustotal {
	$BODY = @{ "apikey" = "$VIRUSTOTAL_API_KEY"; "file" = "$FILEPATH" }
	$SCAN = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/scan' -Body $BODY
	$HASH = $SCAN.sha256
	Start-Sleep -s 15
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
			Submit-CHECKPHISH
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
		}
	}
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
			Submit-URL-Virustotal
			Submit-URLSCAN
			Submit-CHECKPHISH
			Google-Safe-Browsing
		} 
	}else{ Write-OutPut "=====================No URL in the PDF/HTML file needs to scan=====================" >> $LOGFILE }
	$extractor.Reset()
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
	$FOLDERID = ($INBOX.FindFolders([Microsoft.Exchange.WebServices.Data.FolderView]::new(10)) | where { $_.DisplayName -eq $SUBFOLDER }).Id.UniqueID
	$PROPERTYSET = new-object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::FirstClassProperties)
	$PROPERTYSET.RequestedBodyType = [Microsoft.Exchange.WebServices.Data.BodyType]::Text
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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
							Submit-URL-Virustotal
							Submit-URLSCAN
							Submit-CHECKPHISH
							Google-Safe-Browsing
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
							$ATTFILE = new-object System.IO.FileStream(($ATTFILENAME), [System.IO.FileMode]::Create)
							$ATTFILE.Write($AttachmentData, 0, $AttachmentData.Length)
							$ATTFILE.Close()
							Write-OutPut "Downloaded Attachment : "  ($ATTFILENAME) >> $LOGFILE
							$ALGORITHM = (Get-FileHash ($ATTFILENAME)).Algorithm
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
								}else{
									if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){ 
										Submit-FILE-Virustotal
										Submit-FILE-OPSWAT
									}
								}
							}
						}
					}
					Write-OutPut "================================END=================================" >> $LOGFILE
					ConvertLogToHTML
					$REPLYSUBJECT = "AUTO-REPLY/Security Scan Report-- "+$($EMAIL.Subject)
					$SMTPSERVER = Get-Content .\init.conf | findstr SMTPSERVER |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					#$REPLYTO = $($EMAIL.From.Address.ToString()) // If you want to send the scan report to the sender who reported the spam email //
					$REPLYTO = Get-Content .\init.conf | findstr REPLYTO |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					$REPLYCC = Get-Content .\init.conf | findstr REPLYCC |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					$EMAIBODY = '%CUSTOMER_EMAIL=' + $($EMAIL.From.Address) + "`r`n" + '%CUSTOMER=' + $($EMAIL.From.Name) + "`r`n" + '%SUMMARY=Security Scan Report--' + $($EMAIL.Subject)
					Send-MailMessage -SmtpServer $SMTPSERVER -To $REPLYTO -From $EMAILADDRESS -Cc $REPLYCC -Subject $REPLYSUBJECT -Body $EMAIBODY -Attachments $HTMLREPFILE
			}
			$EMAIL.isRead = $true
			$EMAIL.Update([Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AutoResolve)
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
