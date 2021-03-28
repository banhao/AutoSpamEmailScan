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

Version:4.4.1

Update function CheckRedirectedURL{}

Version:4.4.0

If you have Cisco Email Security Appliance in your environment above version 13.5.2 there's a new feature called "Spam Quarantine SafeList and BlockList".

By working with the "Cisco Email Reporting Plug-in" for Outlook, you can let the end users to block spam emails by one click.

# AutoSpamEmailScan
“AutoSpamEmailScan.ps1” is used to monitor a specific mailbox that in enterprise users can forward suspicious spam emails to a specific mailbox. 
This PowerShell script can monitor the mailbox for any unread emails, grab the URLs and attachments from the emails and submit to virustotal.com, urlscan.io, Google safe browsing and OPSWAT. Script also can extract URLs from a pdf file. 
After the scan finished, script can generate HTML format scan report and auto reply to the senders.
Script can be run once or loop interval, if $INTERVAL in the init.conf is 0 means script will only run one time else the number is the loop interval seconds.

Before you run the script Install the Exchange Web Services Managed API 2.2. 
https://www.microsoft.com/en-us/download/details.aspx?id=42951

You also can find this script in powershellgallery.com
https://www.powershellgallery.com/packages/AutoSpamEmailScan/
