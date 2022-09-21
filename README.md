# Auto Spam Email Scan
[![Minimum Supported PowerShell Version](https://img.shields.io/badge/PowerShell-5.1+-purple.svg)](https://github.com/PowerShell/PowerShell) ![Cross Platform](https://img.shields.io/badge/platform-windows-lightgrey)
[![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/AutoSpamEmailScan)](https://www.powershellgallery.com/packages/AutoSpamEmailScan) [![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/AutoSpamEmailScan)](https://www.powershellgallery.com/packages/AutoSpamEmailScan)


UPDATE: Version 5.1.6 September 21, 2022

- Add Hash Value into MineMeld when the attachment scan result is positive


UPDATE: Version 5.1.5 September 09, 2022

- Add module "Base64Decode"


UPDATE: Version 5.1.4 August 17, 2022

- Add module "extract_hyperlink_from_Excel"


UPDATE: Version 5.1.3 June 10, 2022

- optimize some outputs format


UPDATE: Version 5.1.2 May 31, 2022

- Rename some variables. Update "RedirectURL.py"


UPDATE: Version 5.1.1 May 30, 2022

- Optimize the module "CheckRedirectedURL", skip scan the URL if the URL contain file types in variable "$EXTENSIONARRAY" 


UPDATE: Version 5.1.0 May 26, 2022

- Add "RedirectURL.py" to replace the powershell script.
- Add "pdf2url.py" to replace the "Bytescout.PDF2HTML.dll"
- Add "Submit_FILE_Virustotal.py" to replace the "Submit-FILE-Virustotal" and call VirusTotal V3 API


UPDATE: Version 5.0.1 May 03, 2022

 - optimize the method to extract email address from the mail body.


UPDATE: Version 5.0.0 April 29, 2022

 - This version I removed some modules and replaced them by using independ powershell scripts. So I want this one can be more flexible if you want to use this script as a main frame and bulid your own work flow.


<img src="/Work Flow.jpg">


Notice: "Cisco Email Reporting Plug-in" or "NotifySecurity" Plug-in are not necessary. It's just optional for the end users to have the one-click ability. Without these plug-in the end users still can forward the spam emails to a specific mail box for the investigation.

But I still recommend to use "Cisco Email Reporting Plug-in" because after custom the buttons you can do lots of things.

Imagine the following scenario: You have an email security poolicy in your company that all encrypted email will be quarantined by Cisco ESA because the attackers will use encrypted emails to bypass the security inspection. The end users will receive an notification email and asked them to confirm that they known the sender and it's a business related email and they are expecting this email. Then the end users forward the notification email to the Service Desk or Security Team to ask releasing the email from the quarantine. 

So you can involve this "Cisco Email Reporting Plug-in" and make it automatically. You can custom one button and display as "Release this email", when the end users click this button on the notification email, it will be encapsulated as a raw-data and forward to "releaseemail@yourconpany.com". You can run a script to monitor "releaseemail@yourconpany.com" and grab the information from the email and call the ESA API to release the emails from the quarantine.

“AutoSpamEmailScan.ps1” is using the same manner to call the ESA API to build a blocklist for the endusers.

<img src="/procedure.jpg">

There are 2 ways to intergrate the Plug-in on Office Outlook. "Cisco Email Reporting Plug-in" and "NotifySecurity" which I forked "https://github.com/banhao/NotifySecurity"

I prefer to use "Cisco Email Reporting Plug-in" which you can custom the button.

<img src="/plug-in.jpg">

And also can custom the action when end users click the different buttons.

```
<?xml version="1.0" encoding="utf-8"?>
<reporting xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <reportingComponent>
    <lockUiOptions>false</lockUiOptions>
    <enabled>true</enabled>
    <keepSentReports>true</keepSentReports>
    <report>
      <format>plain</format>
      <subject>Cisco Email Reporting Plug-in Report ${reportType}</subject>
    </report>
    <maxMailSize>1005000</maxMailSize>
    <attachmentName>orig_mas.raw</attachmentName>
    <showReportSuccessOne>true</showReportSuccessOne>
    <showReportSuccessMultiple>true</showReportSuccessMultiple>
    <addExplorerCommandBar>true</addExplorerCommandBar>
    <addInspectorCommandBar>true</addInspectorCommandBar>
    <addContextMenu>true</addContextMenu>
    <reportTypes>
      <reportType name="spam">
        <address>spam@company.com</address>
        <copyAddressInPlainFormat />
        <headerValue>spam</headerValue>
        <showInDeletedFolder>false</showInDeletedFolder>
        <showInJunkFolder>true</showInJunkFolder>
        <largeRibbonButton>true</largeRibbonButton>
        <copyAddressOriginal />
      </reportType>
      <reportType name="ham">
        <address>ham@company.com</address>
        <copyAddressInPlainFormat />
        <headerValue>ham</headerValue>
        <showInDeletedFolder>false</showInDeletedFolder>
        <showInJunkFolder>false</showInJunkFolder>
        <largeRibbonButton>true</largeRibbonButton>
        <copyAddressOriginal />
      </reportType>
      <reportType name="virus">
        <address>virus@company.com</address>
        <copyAddressInPlainFormat />
        <headerValue>virus</headerValue>
        <showInDeletedFolder>true</showInDeletedFolder>
        <showInJunkFolder>false</showInJunkFolder>
        <largeRibbonButton>false</largeRibbonButton>
        <copyAddressOriginal />
      </reportType>
      <reportType name="phish">
        <address>phish@company.com</address>
        <copyAddressInPlainFormat />
        <headerValue>phish</headerValue>
        <showInDeletedFolder>true</showInDeletedFolder>
        <showInJunkFolder>false</showInJunkFolder>
        <largeRibbonButton>true</largeRibbonButton>
        <copyAddressOriginal />
      </reportType>
      <reportType name="marketing">
        <address>marketing@company.com</address>
        <copyAddressInPlainFormat />
        <headerValue>marketing</headerValue>
        <showInDeletedFolder>false</showInDeletedFolder>
        <showInJunkFolder>true</showInJunkFolder>
        <largeRibbonButton>true</largeRibbonButton>
        <copyAddressOriginal />
      </reportType>
    </reportTypes>
  </reportingComponent>
</reporting>
```

# AutoSpamEmailScan
“AutoSpamEmailScan.ps1” is used to monitor a specific mailbox that enterprise users can forward suspicious spam emails to a specific mailbox. 
This PowerShell script can monitor the mailbox for any unread emails, grab the URLs and attachments from the emails and submit to virustotal.com, urlscan.io, Google safe browsing and OPSWAT. Script also can extract URLs from a pdf file. 
After the scan finished, script can generate HTML format scan report and auto reply to the senders.
Script can be run once or loop interval, if $INTERVAL in the init.conf is 0 means script will only run one time else the number is the loop interval seconds.

Before you run the script Install the Exchange Web Services Managed API 2.2. 
https://www.microsoft.com/en-us/download/details.aspx?id=42951

You also can find this script in powershellgallery.com
https://www.powershellgallery.com/packages/AutoSpamEmailScan/
