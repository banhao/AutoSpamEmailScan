# AutoSpamEmailScan
“AutoSpamEmailScan.ps1” is used to monitor a specific mailbox that in enterprise users can forward suspicious spam emails to a specific mailbox. 
This PowerShell script can monitor the mailbox for any unread emails, grab the URLs and attachments from the emails and submit to virustotal.com, urlscan.io, Google safe browsing and OPSWAT. Script also can extract URLs from a pdf file. 
After the scan finished, script can generate HTML format scan report and auto reply to the senders.
Script can be run once or loop interval, if $INTERVAL in the init.conf is 0 means script will only run one time else the number is the loop interval seconds.

Before you run the script Install the Exchange Web Services Managed API 2.2. 
https://www.microsoft.com/en-us/download/details.aspx?id=42951

You also can find this script in powershellgallery.com
https://www.powershellgallery.com/packages/AutoSpamEmailScan/4.0.2
