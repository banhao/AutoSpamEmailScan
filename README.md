# AutoSpamEmailScan
“AutoSpamEmailScan.ps1” is used to monitor a specific mailbox that in enterprise the users can forward suspicious spam emails to a  specific mailbox. 
This PowerShell script can monitor the mailbox for any unread emails, grab the URLs and attachments from the emails and submit to virustotal.com, urlscan.io and Google safe browsing.
After the scan finished, script can generate HTML format scan report and auto reply to the senders.
Script can be run once or loop interval, only set the $INTERVAL in the init.conf file.

Before you run the script Install the Exchange Web Services Managed API 2.2. 
https://www.microsoft.com/en-us/download/details.aspx?id=42951
