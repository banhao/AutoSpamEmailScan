
<#PSScriptInfo

.VERSION 5.1.1

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
	Creation Date:  <05/30/2022>
	Purpose/Change: Optimize the module "CheckRedirectedURL", skip scan the URL if the URL contain file types in variable "$EXTENSIONARRAY" 
	
	Creation Date:  <05/26/2022>
	Purpose/Change: Add "RedirectURL.py" to replace the powershell script.
					Add "pdf2url.py" to replace the "Bytescout.PDF2HTML.dll"
					Add "Submit_FILE_Virustotal.py" to replace the "Submit-FILE-Virustotal" and call VirusTotal V3 API
	
	Creation Date:  <05/09/2022>
	Purpose/Change: Add "selenium_simulator.py" to open HTML file on local and get screenshot. 
	
	Creation Date:  <05/03/2022>
	Purpose/Change: optimize the method to extract email address from the mail body.
	
	Creation Date:  <04/28/2022>
	Purpose/Change: Instead the "Cisco SecureX Investigation Module" with the "secureX.ps1"
					Add "MineMeld_Indicator.ps1"
					Add ESA_Spam_Block.ps1
					Remove "checkphish.ai" module
	
	Creation Date:  <09/20/2021>
	Purpose/Change: Fixed Function "ESASpamQuarantine" a small bug.
	
	Creation Date:  <07/08/2021>
	Purpose/Change: add Cisco SecureX Investigation Module
	
	Creation Date:  <05/26/2021>
	Purpose/Change: Fixed some bugs

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
$EWSDLLPATH = Get-Content .\init.conf | findstr EWSDLLPATH |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
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

$global:enable_SecureX = $false

function Google-Safe-Browsing {
	Write-OutPut "Google Safe Browsing Scan Report: " >> $LOGFILE
	$BODY = @()
	$BODY +=[pscustomobject]@{"client" = @{"clientId" = "eHealth Saskatche"; "clientVersion" = "1.0"}; "threatInfo" = @{"threatTypes" = "MALWARE","SOCIAL_ENGINEERING"; "platformTypes" = "WINDOWS"; "threatEntryTypes" = "URL"; "threatEntries" = @{"url" = "$URL"}}}
	$HEADERS = @{ 'Content-Type' = "application/json" }
	$JSONBODY = $BODY | ConvertTo-Json
	$Uri = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+ $GOOGLE_API_KEY
	$Results = Invoke-RestMethod -Method 'POST' -Uri $Uri -Body $JSONBODY -Headers $HEADERS
	if ( ([string]::IsNullOrEmpty($Results)) ) {
		Write-OutPut "Can not find the result in Google Safe Browsing Scan."  >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	 }else{
		$ThreatType = $Results | select -expand matches | select threatType
		if ( ($ThreatType.threatType -eq "SOCIAL_ENGINEERING") -or ($ThreatType.threatType -eq "MALWARE") -or ($ThreatType.threatType -eq "POTENTIALLY_HARMFUL_APPLICATION") ) { $global:enable_SecureX = $true }
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
	if ( ($SCANRESULTS.data.attributes.last_analysis_stats.malicious -gt 0) -or ($SCANRESULTS.data.attributes.last_analysis_stats.suspicious -gt 0) ) { $global:enable_SecureX = $true }
	Write-OutPut "VirusTotal URL COMMUNITY VOTES : " >> $LOGFILE
	Write-OutPut $SCANRESULTS.data.attributes.total_votes >> $LOGFILE
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
		Write-OutPut "$($SCANRESULT.scan_results.total_detected_avs)         |   $($SCANRESULT.scan_results.total_avs)" >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}else {
		Write-OutPut "OPSWAT MetaDefender Cloud File Scan Report: " >> $LOGFILE
		$RESULTLINK = 'https://metadefender.opswat.com/results#!/file/'+$HASH+'/hash/overview'
		Write-OutPut $RESULTLINK >> $LOGFILE
		Write-OutPut "POSITIVES |   TOTAL" >> $LOGFILE
		Write-OutPut "$($SCANRESULT.scan_results.total_detected_avs)         |   $($SCANRESULT.scan_results.total_avs)" >> $LOGFILE
		Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	}
}

function FromEmailAttachment {
	$EMLData = Get-Content $Args[0]
	$AdoDbStream = New-Object -ComObject ADODB.Stream
	$AdoDbStream.Open()
	$AdoDbStream.LoadFromFile($Args[0])
	$global:CdoMessage = New-Object -ComObject CDO.Message
	$CdoMessage.DataSource.OpenObject($AdoDbStream,"_Stream")
	Write-OutPut "===From:    ",$($CdoMessage.From) >> $LOGFILE
	Write-OutPut "===To:    ",$($CdoMessage.To) >> $LOGFILE
	Write-OutPut "===Subject:    ",$($CdoMessage.Subject) >> $LOGFILE
	Write-OutPut "===DateTimeReceived:    ",$($CdoMessage.SentOn) >> $LOGFILE
	Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
	$TextBody = $CdoMessage.Fields.Item("urn:schemas:httpmail:textdescription").Value
	$HTMLBody = $CdoMessage.Fields.Item("urn:schemas:httpmail:htmldescription").Value
	$EmailBODY = $TextBody + $HTMLBody + $EMLData
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
		if ( -not [string]::IsNullOrEmpty($FILENAME) ){
			$TRIMNUM = $ATTACHDATA.LastIndexOf("  ")+2
			$ATTACHMENTDATA = $ATTACHDATA.Remove(0,$TRIMNUM)
			$ATTFILENAME = ($DOWNLOADDIRECTORY + $FILENAME.split('.')[0].trim() + "_" + $RANDOMID + "." + $FILENAME.split('.')[-1].trim())
			Try{ $bytes = [Convert]::FromBase64String($ATTACHMENTDATA) } catch { $Exception = $_.Exception }
			if ( -not ([string]::IsNullOrEmpty($Exception)) ) {
				Write-Output "Exception Error:" $Exception.description >> $LOGFILE
				Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE 
			}
			if ( -not ([string]::IsNullOrEmpty($bytes)) ) { 
				[IO.File]::WriteAllBytes($ATTFILENAME, $bytes)
				Write-OutPut "Downloaded Attachment : Original File $($FILENAME) Saved As $($ATTFILENAME) " >> $LOGFILE
				Try { $ALGORITHM = (Get-FileHash ($ATTFILENAME)).Algorithm }
				Catch [System.SystemException] { $ExceptionError = $_.Exception.Message }
				if ( [string]::IsNullOrEmpty($ExceptionError) ) {
					$HASH = (Get-FileHash ($ATTFILENAME)).Hash.ToLower()
					$FILEPATH = (Get-FileHash ($ATTFILENAME)).Path
					Write-OutPut "Attachment $ALGORITHM Hash : "  $HASH >> $LOGFILE
					$EXTENSION = [System.IO.Path]::GetExtension($ATTFILENAME)
					if ( ($EXTENSION -eq ".pdf") -or ($EXTENSION -eq ".htm") -or ($EXTENSION -eq ".html") -or ($EXTENSION -eq ".shtml") ){
						Write-OutPut "=====================Submit File to VirusTotal and OPSWAT=====================" >> $LOGFILE
						python Submit_FILE_Virustotal.py $FILEPATH >> $LOGFILE
						Submit-FILE-OPSWAT
						Write-OutPut "=====================Extract URLs from the PDF/HTML file=====================" >> $LOGFILE
						ExtractURLFromPDFHTML
						Write-OutPut "=====================Selenimu Simulator=====================" >> $LOGFILE
						python selenium_simulator.py $ATTFILENAME $LOGFILE >> $LOGFILE
					}else {
						if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){
							Write-OutPut "=====================Submit File to VirusTotal and OPSWAT=====================" >> $LOGFILE
							python Submit_FILE_Virustotal.py $FILEPATH >> $LOGFILE
							Submit-FILE-OPSWAT
						}
					}
				}else {
					Write-OutPut "********************************************************************" >> $LOGFILE
					Write-Output "Exception Error:" $ExceptionError >> $LOGFILE   
					Write-OutPut "********************************************************************" >> $LOGFILE
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
		$URLArrayFromPDF = & python pdf2url.py $ATTFILENAME
	}else{
		$HTMLFILE = $ATTFILENAME
		$URLArrayFromHTML = Get-Content $HTMLFILE | select-string -pattern $URLRegEx -AllMatches | %{ $_.Matches } | %{ $_.Value } | Sort-Object | Get-Unique
	}
	if ( ![string]::IsNullOrEmpty($URLArrayFromPDF) -and ![string]::IsNullOrEmpty($URLArrayFromHTML) ) {
		$URLLIST = $URLArrayFromHTML + $URLArrayFromPDF | Sort-Object | Get-Unique
	}elseif( [string]::IsNullOrEmpty($URLArrayFromPDF) -and ![string]::IsNullOrEmpty($URLArrayFromHTML) ) {
		$URLLIST = $URLArrayFromHTML | Sort-Object | Get-Unique
	}elseif( ![string]::IsNullOrEmpty($URLArrayFromPDF) -and [string]::IsNullOrEmpty($URLArrayFromHTML) ) {
		$URLLIST = $URLArrayFromPDF | Sort-Object | Get-Unique
	}
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
	if ( $URL -like '*safelinks.protection.outlook.com*' ) { $URL = [System.Web.HttpUtility]::ParseQueryString($(New-Object -TypeName System.Uri -ArgumentList $URL).Query)["url"] }
	Write-Output "The Original URL is:" $URL >> $LOGFILE
	$OriginalURL = $URL
	$URLAccessible = & python RedirectURL.py $URL
	if ($URLAccessible -match "is not accessible.") {
		Write-OutPut "$($URL) is not accessible." >> $LOGFILE
	}else{
		$RedirectedURL = $URLAccessible
		if ($OriginalURL -eq $RedirectedURL) {
			Write-OutPut "    |" >> $LOGFILE
			Write-Output "    |--> The Redirected URL is: $($RedirectedURL)" >> $LOGFILE
			if (! $EXTENSIONARRAY.contains($(($OriginalURL -split "/")[-1]).split(".")[-1])) {
				Submit-URL-Virustotal
				Submit-URLSCAN
				Google-Safe-Browsing
				Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"  >> $LOGFILE
				if ( $global:enable_SecureX ) {
					.\MineMeld_Indicator.ps1 $URL URL -comment "User Reported" >> $LOGFILE
					Write-OutPut "$($URL) has been added into MineMeld." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					.\secureX.ps1 $URL >> $LOGFILE
					Write-OutPut "secureX and MDATP investigation is done." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					if ( ![string]::IsNullOrEmpty($CdoMessage) ) {
						$regex = [regex]"\<(.*)\>"
						$Blocklist_Sender = $($regex.match($($CdoMessage.From)).Groups[1].value).ToLower()
					}else{
						$regex = "From:.*?(?<=[\[\<]).+?(?=[\]\>])"
						$regex_eml = '([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)'
						if ( @([regex]::Matches($EMAIL.Body.Text, $regex).value).length -gt 1 ) { $Blocklist_Sender = [regex]::Matches($([regex]::Matches($EMAIL.Body.Text, $regex).Value[-1]), $regex_eml).value[-1] }else{  $Blocklist_Sender = [regex]::Matches($([regex]::Matches($EMAIL.Body.Text, $regex).Value), $regex_eml).value }
						}
					.\ESA_Spam_Block.ps1 $Blocklist_Sender ALL >> $LOGFILE
					Write-OutPut "SPAM Sender $($Blocklist_Sender) has been blacklisted." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					$global:enable_SecureX = $false
				}
			}
		}else{
			$URL = $OriginalURL
			if (! $EXTENSIONARRAY.contains($(($URL -split "/")[-1]).split(".")[-1])) {
				Submit-URL-Virustotal
				Submit-URLSCAN
				Google-Safe-Browsing
				Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"  >> $LOGFILE
				if ( $global:enable_SecureX ) {
					.\MineMeld_Indicator.ps1 $URL URL -comment "User Reported" >> $LOGFILE
					Write-OutPut "$($URL) has been added into MineMeld." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					.\secureX.ps1 $URL >> $LOGFILE
					Write-OutPut "secureX and MDATP investigation is done." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					if ( ![string]::IsNullOrEmpty($CdoMessage) ) {
						$regex = [regex]"\<(.*)\>"
						$Blocklist_Sender = $($regex.match($($CdoMessage.From)).Groups[1].value).ToLower()
					}else{
						$regex = "From:.*?(?<=[\[\<]).+?(?=[\]\>])"
						$regex_eml = '([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)'
						if ( @([regex]::Matches($EMAIL.Body.Text, $regex).value).length -gt 1 ) { $Blocklist_Sender = [regex]::Matches($([regex]::Matches($EMAIL.Body.Text, $regex).Value[-1]), $regex_eml).value[-1] }else{  $Blocklist_Sender = [regex]::Matches($([regex]::Matches($EMAIL.Body.Text, $regex).Value), $regex_eml).value }
						}
					.\ESA_Spam_Block.ps1 $Blocklist_Sender ALL >> $LOGFILE
					Write-OutPut "SPAM Sender $($Blocklist_Sender) has been blacklisted." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					$global:enable_SecureX = $false
				}
			}
			$URL = $RedirectedURL
			if (! $EXTENSIONARRAY.contains($(($URL -split "/")[-1]).split(".")[-1])) {
				Submit-URL-Virustotal
				Submit-URLSCAN
				Google-Safe-Browsing
				Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"  >> $LOGFILE
				if ( $global:enable_SecureX ) {
					.\MineMeld_Indicator.ps1 $URL URL -comment "User Reported" >> $LOGFILE
					Write-OutPut "$($URL) has been added into MineMeld." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					.\secureX.ps1 $URL >> $LOGFILE
					Write-OutPut "secureX and MDATP investigation is done." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					if ( ![string]::IsNullOrEmpty($CdoMessage) ) {
						$regex = [regex]"\<(.*)\>"
						$Blocklist_Sender = $($regex.match($($CdoMessage.From)).Groups[1].value).ToLower()
					}else{
						$regex = "From:.*?(?<=[\[\<]).+?(?=[\]\>])"
						$regex_eml = '([\w-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)'
						if ( @([regex]::Matches($EMAIL.Body.Text, $regex).value).length -gt 1 ) { $Blocklist_Sender = [regex]::Matches($([regex]::Matches($EMAIL.Body.Text, $regex).Value[-1]), $regex_eml).value[-1] }else{  $Blocklist_Sender = [regex]::Matches($([regex]::Matches($EMAIL.Body.Text, $regex).Value), $regex_eml).value }
						}
					.\ESA_Spam_Block.ps1 $Blocklist_Sender ALL >> $LOGFILE
					Write-OutPut "SPAM Sender $($Blocklist_Sender) has been blacklisted." >> $LOGFILE
					Write-OutPut "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOGFILE
					$global:enable_SecureX = $false
				}
			}
		}
	}
	Write-OutPut "====================================================================" >> $LOGFILE
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
#	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
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
				if( ($EMAIL.Subject -ne "Thank you for contacting the eHealth Saskatchewan Service Desk") -or ($EMAIL.Subject -ne "Service Desk Auto Reply for emailsecurity@ehealthsask.ca") ){
					# load the property set to get to the body
					$EMAIL.load($PROPERTYSET)
					$RANDOMID = -join ((48..57) + (97..122) | Get-Random -Count 20 | % {[char]$_})
					$LOGFILE = $REPORTSDIRECTORY+"security-scan-report_"+$RANDOMID+".log"
					$HTMLREPFILE = $REPORTSDIRECTORY+"security-scan-report_"+$RANDOMID+".html"
					$SCREENSHOTFILE = $REPORTSDIRECTORY+"screenshot_"+$RANDOMID+".jpg"
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
											if ( ($EXTENSION -eq ".pdf") -or ($EXTENSION -eq ".htm") -or ($EXTENSION -eq ".html") -or ($EXTENSION -eq ".shtml") ){
												Write-OutPut "=====================Submit File to VirusTotal and OPSWAT=====================" >> $LOGFILE
												python Submit_FILE_Virustotal.py $FILEPATH >> $LOGFILE
												Submit-FILE-OPSWAT
												Write-OutPut "=====================Extract URLs from the PDF/HTML file=====================" >> $LOGFILE
												ExtractURLFromPDFHTML
												Write-OutPut "=====================Selenimu Simulator=====================" >> $LOGFILE
												python selenium_simulator.py $ATTFILENAME $LOGFILE >> $LOGFILE
											}else {
												if ( -not ([string]::IsNullOrEmpty($FILEPATH)) ){
													python Submit_FILE_Virustotal.py $FILEPATH >> $LOGFILE
													Submit-FILE-OPSWAT
												}
												}
										}
								} else {
									Write-OutPut "********************************************************************" >> $LOGFILE
									Write-Output "Exception Error:" $ExceptionError >> $LOGFILE   
									Write-OutPut "********************************************************************" >> $LOGFILE
									}
							} else {
									Write-OutPut "********************************************************************" >> $LOGFILE
									Write-Output "Exception Error:" $ExceptionError >> $LOGFILE   
									Write-OutPut "********************************************************************" >> $LOGFILE
								}		
						}
					}
					Write-OutPut "================================END=================================" >> $LOGFILE
					ConvertLogToHTML
					$REPLYSUBJECT = "AUTO-REPLY/Security Scan Report-- "+$($EMAIL.Subject)
					$SMTPSERVER = Get-Content .\init.conf | findstr SMTPSERVER |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					$REPLYTO = Get-Content .\init.conf | findstr REPLYTO |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					$REPLYCC = Get-Content .\init.conf | findstr REPLYCC |  %{ $_.Split('=')[1]; } | foreach{ $_.ToString().Trim() }
					$EMAIBODY = '%CUSTOMER_EMAIL=' + $($EMAIL.From.Address) + "`r`n" + '%CUSTOMER=' + $($EMAIL.From.Name) + "`r`n" + '%SUMMARY=Security Scan Report--' + $($EMAIL.Subject)
					if ( Test-Path -Path $SCREENSHOTFILE ) {
						$ATTACHMENTS = @($HTMLREPFILE, $SCREENSHOTFILE)	
						Send-MailMessage -SmtpServer $SMTPSERVER -To $REPLYTO -From $EMAILADDRESS -Cc $REPLYCC -Subject $REPLYSUBJECT -Body $EMAIBODY -Attachments $ATTACHMENTS
					}else {
						Send-MailMessage -SmtpServer $SMTPSERVER -To $REPLYTO -From $EMAILADDRESS -Cc $REPLYCC -Subject $REPLYSUBJECT -Body $EMAIBODY -Attachments $HTMLREPFILE
					}
				}
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
