# Splunk threat hunting queries
(Ref :- https://docs.google.com/spreadsheets/d/12y5F-7CK-HQV71sp5sjxBQqO0X9fXrE8tYIsSPFrnCg/)


Active Directory User Backdoors
	
	(EventID="4738" AllowedToDelegateTo="*") OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo") OR (EventID="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")


Activity Related to NTDS.dit Domain Hash Retrieval
	
	(EventID="1" (CommandLine="vssadmin.exe Delete Shadows" OR CommandLine="vssadmin create shadow /for=C:" OR CommandLine="copy \\\\?\\GLOBALROOT\\Device\\*\\windows\\ntds\\ntds.dit" OR CommandLine="copy \\\\?\\GLOBALROOT\\Device\\*\\config\\SAM" OR CommandLine="vssadmin delete shadows /for=C:" OR CommandLine="reg SAVE HKLM\\SYSTEM "))


Addition of SID History to Active Directory Object
	
	((EventID="4765" OR EventID="4766"))


Admin User Remote Logon
	
	(EventID="4624" LogonType="10" AuthenticationPackageName="Negotiate" AccountName="Admin-*")


Apache Segmentation Fault
	
	("exit signal Segmentation Fault")


APT User Agent
	
	((UserAgent="SJZJ (compatible; MSIE 6.0; Win32)" OR UserAgent="Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0" OR UserAgent="User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC" OR UserAgent="Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)" OR UserAgent="webclient" OR UserAgent="Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" OR UserAgent="Mozilla/4.0 (compatible; MSI 6.0;" OR UserAgent="Mozilla/5.0 (Windows NT 6.3; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0" OR UserAgent="Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" OR UserAgent="Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" OR UserAgent="Mozilla/4.0" OR UserAgent="Netscape" OR UserAgent="Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7" OR UserAgent="Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Firefox/3.6.13 GTB7.1" OR UserAgent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Win32)"))


Backup Catalog Deleted
	
	(EventID="524" Source="Backup")


Bitsadmin Download
	
	(EventID="1" (Image="*\\bitsadmin.exe") (CommandLine="/transfer"))


Buffer Overflow Attempts
	
	("attempt to execute code on stack by" OR "FTP LOGIN FROM .* 0bin0sh" OR "rpc.statd[\\d+]: gethostbyname error for" OR "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


cmdkey Cached Credentials Recon
	
	(EventID="1" Image="*\\cmdkey.exe" CommandLine="* /list *")


Command Line Execution with suspicious URL and AppData Strings
	
	(EventID="1" (CommandLine="cmd.exe /c *http://*%AppData%" OR CommandLine="cmd.exe /c *https://*%AppData%"))


Detection MavInject32.exe execution
	
	(EventID="1" (ParentImage="*\\cmd.exe") (Image="C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\MavInject32.exe") (ParentCommandLine="*\\cmd.exe") (CommandLine="*\\MavInject32.exe*")) OR ("INJECTRUNNING")

Detects malware AcroRD32.exe execution process
	
	(EventID="1" Image="*\\AcroRD32.exe") NOT ((Image="*\\Adobe\\Acrobat Reader DC\\Reader\\AcroRD32.exe"))

Detects Suspicious Commands on Linux systems
	
	(type="EXECVE" a0="chmod" a1="777" OR type="EXECVE" a0="chmod" a1="u+s" OR type="EXECVE" a0="cp" a1="/bin/ksh" OR type="EXECVE" a0="cp" a1="/bin/sh")

DHCP Callout DLL installation
	
	(EventID="13" (TargetObject="*\\Services\\DHCPServer\\Parameters\\CalloutDlls" OR TargetObject="*\\Services\\DHCPServer\\Parameters\\CalloutEnabled"))

DHCP Server Error Failed Loading the CallOut DLL
	
	((EventID="1031" OR EventID="1032" OR EventID="1034"))

DHCP Server Loaded the CallOut DLL
	
	(EventID="1033")

Disabling Windows Event Auditing
	
	(EventID="4719" AuditPolicyChanges="removed")

DiskShadow and Vshadow launch detection	

	(EventID="1" (ParentImage="*\\vshadow.exe") (Image="*\\notepad.exe")) OR (EventID="1" (ParentImage="*\\diskshadow.exe") (Image="*\\notepad.exe")) OR (EventID="1" (CommandLine="vshadow.exe -nw -exec=c:\\windows\\system32\\notepad.exe c:" OR CommandLine="diskshadow.exe /s c:\\*"))

Django framework exceptions
	
	("SuspiciousOperation" OR "DisallowedHost" OR "DisallowedModelAdminLookup" OR "DisallowedModelAdminToField" OR "DisallowedRedirect" OR "InvalidSessionKey" OR "RequestDataTooBig" OR "SuspiciousFileOperation" OR "SuspiciousMultipartForm" OR "SuspiciousSession" OR "TooManyFieldsSent" OR "PermissionDenied")

DNS Server Error Failed Loading the ServerLevelPluginDLL
	
	((EventID="150" OR EventID="770"))

DNS ServerLevelPluginDll Install
	
	(EventID="1" CommandLine="dnscmd.exe /config /serverlevelplugindll *") OR (EventID="13" TargetObject="*\\services\\DNS\\Parameters\\ServerLevelPluginDll")

Download EXE from Suspicious TLD
	
	((c-uri-extension="exe" OR c-uri-extension="vbs" OR c-uri-extension="bat" OR c-uri-extension="rar" OR c-uri-extension="ps1" OR c-uri-extension="doc" OR c-uri-extension="docm" OR c-uri-extension="xls" OR c-uri-extension="xlsm" OR c-uri-extension="pptm" OR c-uri-extension="rtf" OR c-uri-extension="hta" OR c-uri-extension="dll" OR c-uri-extension="ws" OR c-uri-extension="wsf" OR c-uri-extension="sct" OR c-uri-extension="zip")) NOT ((r-dns="*.com" OR r-dns="*.org" OR r-dns="*.net" OR r-dns="*.edu" OR r-dns="*.gov" OR r-dns="*.uk" OR r-dns="*.ca" OR r-dns="*.de" OR r-dns="*.jp" OR r-dns="*.fr" OR r-dns="*.au" OR r-dns="*.us" OR r-dns="*.ch" OR r-dns="*.it" OR r-dns="*.nl" OR r-dns="*.se" OR r-dns="*.no" OR r-dns="*.es"))

Download from Suspicious Dyndns Hosts
	
	((c-uri-extension="exe" OR c-uri-extension="vbs" OR c-uri-extension="bat" OR c-uri-extension="rar" OR c-uri-extension="ps1" OR c-uri-extension="doc" OR c-uri-extension="docm" OR c-uri-extension="xls" OR c-uri-extension="xlsm" OR c-uri-extension="pptm" OR c-uri-extension="rtf" OR c-uri-extension="hta" OR c-uri-extension="dll" OR c-uri-extension="ws" OR c-uri-extension="wsf" OR c-uri-extension="sct" OR c-uri-extension="zip") (r-dns="*.hopto.org" OR r-dns="*.no-ip.org" OR r-dns="*.no-ip.info" OR r-dns="*.no-ip.biz" OR r-dns="*.no-ip.com" OR r-dns="*.noip.com" OR r-dns="*.ddns.name" OR r-dns="*.myftp.org" OR r-dns="*.myftp.biz" OR r-dns="*.serveblog.net" OR r-dns="*.servebeer.com" OR r-dns="*.servemp3.com" OR r-dns="*.serveftp.com" OR r-dns="*.servequake.com" OR r-dns="*.servehalflife.com" OR r-dns="*.servehttp.com" OR r-dns="*.servegame.com" OR r-dns="*.servepics.com" OR r-dns="*.myvnc.com" OR r-dns="*.ignorelist.com" OR r-dns="*.jkub.com" OR r-dns="*.dlinkddns.com" OR r-dns="*.jumpingcrab.com" OR r-dns="*.ddns.info" OR r-dns="*.mooo.com" OR r-dns="*.dns-dns.com" OR r-dns="*.strangled.net" OR r-dns="*.ddns.info" OR r-dns="*.adultdns.net" OR r-dns="*.craftx.biz" OR r-dns="*.ddns01.com" OR r-dns="*.dns53.biz" OR r-dns="*.dnsapi.info" OR r-dns="*.dnsd.info" OR r-dns="*.dnsdynamic.com" OR r-dns="*.dnsdynamic.net" OR r-dns="*.dnsget.org" OR r-dns="*.fe100.net" OR r-dns="*.flashserv.net" OR r-dns="*.ftp21.net" OR r-dns="*.http01.com" OR r-dns="*.http80.info" OR r-dns="*.https443.com" OR r-dns="*.imap01.com" OR r-dns="*.kadm5.com" OR r-dns="*.mysq1.net" OR r-dns="*.ns360.info" OR r-dns="*.ntdll.net" OR r-dns="*.ole32.com" OR r-dns="*.proxy8080.com" OR r-dns="*.sql01.com" OR r-dns="*.ssh01.com" OR r-dns="*.ssh22.net" OR r-dns="*.tempors.com" OR r-dns="*.tftpd.net" OR r-dns="*.ttl60.com" OR r-dns="*.ttl60.org" OR r-dns="*.user32.com" OR r-dns="*.voip01.com" OR r-dns="*.wow64.net" OR r-dns="*.x64.me" OR r-dns="*.xns01.com" OR r-dns="*.dyndns.org" OR r-dns="*.dyndns.info" OR r-dns="*.dyndns.tv" OR r-dns="*.dyndns-at-home.com" OR r-dns="*.dnsomatic.com" OR r-dns="*.zapto.org" OR r-dns="*.webhop.net" OR r-dns="*.25u.com" OR r-dns="*.slyip.net"))

Download from Suspicious TLD
	
	((c-uri-extension="exe" OR c-uri-extension="vbs" OR c-uri-extension="bat" OR c-uri-extension="rar" OR c-uri-extension="ps1" OR c-uri-extension="doc" OR c-uri-extension="docm" OR c-uri-extension="xls" OR c-uri-extension="xlsm" OR c-uri-extension="pptm" OR c-uri-extension="rtf" OR c-uri-extension="hta" OR c-uri-extension="dll" OR c-uri-extension="ws" OR c-uri-extension="wsf" OR c-uri-extension="sct" OR c-uri-extension="zip") (r-dns="*.country" OR r-dns="*.stream" OR r-dns="*.gdn" OR r-dns="*.mom" OR r-dns="*.xin" OR r-dns="*.kim" OR r-dns="*.men" OR r-dns="*.loan" OR r-dns="*.download" OR r-dns="*.racing" OR r-dns="*.online" OR r-dns="*.science" OR r-dns="*.ren" OR r-dns="*.gb" OR r-dns="*.win" OR r-dns="*.top" OR r-dns="*.review" OR r-dns="*.vip" OR r-dns="*.party" OR r-dns="*.tech" OR r-dns="*.tech" OR r-dns="*.xyz" OR r-dns="*.date" OR r-dns="*.faith" OR r-dns="*.zip" OR r-dns="*.cricket" OR r-dns="*.space" OR r-dns="*.top" OR r-dns="*.info" OR r-dns="*.vn" OR r-dns="*.cm" OR r-dns="*.am" OR r-dns="*.cc" OR r-dns="*.asia" OR r-dns="*.ws" OR r-dns="*.tk" OR r-dns="*.biz" OR r-dns="*.su" OR r-dns="*.st" OR r-dns="*.ro" OR r-dns="*.ge" OR r-dns="*.ms" OR r-dns="*.pk" OR r-dns="*.nu" OR r-dns="*.me" OR r-dns="*.ph" OR r-dns="*.to" OR r-dns="*.tt" OR r-dns="*.name" OR r-dns="*.tv" OR r-dns="*.tv" OR r-dns="*.kz" OR r-dns="*.tc" OR r-dns="*.mobi" OR r-dns="*.study" OR r-dns="*.click" OR r-dns="*.link" OR r-dns="*.trade" OR r-dns="*.accountant"))

Droppers exploiting CVE-2017-11882
	
	(EventID="1" ParentImage="*\\EQNEDT32.EXE")

DualToy Trojan Detection
	
	((r-dns="www.zaccl.com" OR r-dns="pack.1e5.com" OR r-dns="rsys.topfreeweb.net" OR r-dns="abc.yuedea.com" OR r-dns="report.boxlist.info" OR r-dns="tt.51wanyx.net" OR r-dns="hk.pk2012.info" OR r-dns="center.oldlist.info" OR r-dns="up.top258.cn" OR r-dns="dl.dswzd.com"))

Elise Backdoor
	
	(EventID="1" Image="C:\\Windows\\SysWOW64\\cmd.exe" CommandLine="*\\Windows\\Caches\\NavShExt.dll *") OR (EventID="1" CommandLine="*\\AppData\\Roaming\\MICROS~1\\Windows\\Caches\\NavShExt.dll,Setting")

Empty User Agent
	
	((UserAgent=""))

Enabled User Right in AD to Control User Objects
	
	(EventID="4707") ("SeEnableDelegationPrivilege")

Enabling RDP remotely using PsExec
	
	(EventID="1" Image="*\\reg.exe" CommandLine="\"reg\" add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f" ParentCommandLine="*\\PSEXESVC.exe")

Equation Group C2 Communication
	
	((dst="69.42.98.86" OR dst="89.185.234.145")) OR ((src="69.42.98.86" OR src="89.185.234.145"))

Equation Group Indicators
	
	("chown root*chmod 4777 " OR "cp /bin/sh .;chown" OR "chmod 4777 /tmp/.scsi/dev/bin/gsh" OR "chown root:root /tmp/.scsi/dev/bin/" OR "chown root:root x;" OR "/bin/telnet locip locport < /dev/console | /bin/sh" OR "/tmp/ratload" OR "ewok -t " OR "xspy -display " OR "cat > /dev/tcp/127.0.0.1/80 <<END" OR "rm -f /current/tmp/ftshell.latest" OR "ghost_* -v " OR " --wipe > /dev/null" OR "ping -c 2 *; grep * /proc/net/arp >/tmp/gx" OR "iptables * OUTPUT -p tcp -d 127.0.0.1 --tcp-flags RST RST -j DROP;" OR "> /var/log/audit/audit.log; rm -f ." OR "cp /var/log/audit/audit.log .tmp" OR "sh >/dev/tcp/* <&1 2>&1" OR "ncat -vv -l -p * <" OR "nc -vv -l -p * <" OR "< /dev/console | uudecode && uncompress" OR "sendmail -osendmail;chmod +x sendmail" OR "/usr/bin/wget -O /tmp/a http* && chmod 755 /tmp/cron" OR "chmod 666 /var/run/utmp~" OR "chmod 700 nscd crond" OR "cp /etc/shadow /tmp/." OR "</dev/console |uudecode > /dev/null 2>&1 && uncompress" OR "chmod 700 jp&&netstat -an|grep" OR "uudecode > /dev/null 2>&1 && uncompress -f * && chmod 755" OR "chmod 700 crond" OR "wget http*; chmod +x /tmp/sendmail" OR "chmod 700 fp sendmail pt" OR "chmod 755 /usr/vmsys/bin/pipe" OR "chmod -R 755 /usr/vmsys" OR "chmod 755 $opbin/*tunnel" OR "< /dev/console | uudecode && uncompress" OR "chmod 700 sendmail" OR "chmod 0700 sendmail" OR "/usr/bin/wget http*sendmail;chmod +x sendmail;" OR "&& telnet * 2>&1 </dev/console")

Eventlog Cleared
	
	(EventID="104" Source="Eventlog")

Eventlog Cleared
	
	(EventID="104")

Executable used by PlugX in Uncommon Location
	
	((EventID="1" Image="*\\CamMute.exe") NOT (EventID="1" Image="*\\Lenovo\\Communication Utility\\*")) OR ((EventID="1" Image="*\\chrome_frame_helper.exe") NOT (EventID="1" Image="*\\Google\\Chrome\\application\\*")) OR ((EventID="1" Image="*\\dvcemumanager.exe") NOT (EventID="1" Image="*\\Microsoft Device Emulator\\*")) OR ((EventID="1" Image="*\\Gadget.exe") NOT (EventID="1" Image="*\\Windows Media Player\\*")) OR ((EventID="1" Image="*\\hcc.exe") NOT (EventID="1" Image="*\\HTML Help Workshop\\*")) OR ((EventID="1" Image="*\\hkcmd.exe") NOT (EventID="1" (Image="*\\System32\\*" OR Image="*\\SysNative\\*" OR Image="*\\SysWowo64\\*"))) OR ((EventID="1" Image="*\\Mc.exe") NOT (EventID="1" (Image="*\\Microsoft Visual Studio*" OR Image="*\\Microsoft SDK*" OR Image="*\\Windows Kit*"))) OR ((EventID="1" Image="*\\MsMpEng.exe") NOT (EventID="1" (Image="*\\Microsoft Security Client\\*" OR Image="*\\Windows Defender\\*" OR Image="*\\AntiMalware\\*"))) OR ((EventID="1" Image="*\\msseces.exe") NOT (EventID="1" Image="*\\Microsoft Security Center\\*")) OR ((EventID="1" Image="*\\OInfoP11.exe") NOT (EventID="1" Image="*\\Common Files\\Microsoft Shared\\*")) OR ((EventID="1" Image="*\\OleView.exe") NOT (EventID="1" (Image="*\\Microsoft Visual Studio*" OR Image="*\\Microsoft SDK*" OR Image="*\\Windows Kit*" OR Image="*\\Windows Resource Kit\\*"))) OR ((EventID="1" Image="*\\OleView.exe") NOT (EventID="1" (Image="*\\Microsoft Visual Studio*" OR Image="*\\Microsoft SDK*" OR Image="*\\Windows Kit*" OR Image="*\\Windows Resource Kit\\*" OR Image="*\\Microsoft.NET\\*")))

Executable used by PlugX in Uncommon Location
	
	((EventID="4688" CommandLine="*\\CamMute.exe") NOT (EventID="4688" CommandLine="*\\Lenovo\\Communication Utility\\*")) OR ((EventID="4688" CommandLine="*\\chrome_frame_helper.exe") NOT (EventID="4688" CommandLine="*\\Google\\Chrome\\application\\*")) OR ((EventID="4688" CommandLine="*\\dvcemumanager.exe") NOT (EventID="4688" CommandLine="*\\Microsoft Device Emulator\\*")) OR ((EventID="4688" CommandLine="*\\Gadget.exe") NOT (EventID="4688" CommandLine="*\\Windows Media Player\\*")) OR ((EventID="4688" CommandLine="*\\hcc.exe") NOT (EventID="4688" CommandLine="*\\HTML Help Workshop\\*")) OR ((EventID="4688" CommandLine="*\\hkcmd.exe") NOT (EventID="4688" (CommandLine="*\\System32\\*" OR CommandLine="*\\SysNative\\*" OR CommandLine="*\\SysWowo64\\*"))) OR ((EventID="4688" CommandLine="*\\Mc.exe") NOT (EventID="4688" (CommandLine="*\\Microsoft Visual Studio*" OR CommandLine="*\\Microsoft SDK*" OR CommandLine="*\\Windows Kit*"))) OR ((EventID="4688" CommandLine="*\\MsMpEng.exe") NOT (EventID="4688" (CommandLine="*\\Microsoft Security Client\\*" OR CommandLine="*\\Windows Defender\\*" OR CommandLine="*\\AntiMalware\\*"))) OR ((EventID="4688" CommandLine="*\\msseces.exe") NOT (EventID="4688" CommandLine="*\\Microsoft Security Center\\*")) OR ((EventID="4688" CommandLine="*\\OInfoP11.exe") NOT (EventID="4688" CommandLine="*\\Common Files\\Microsoft Shared\\*")) OR ((EventID="4688" CommandLine="*\\OleView.exe") NOT (EventID="4688" (CommandLine="*\\Microsoft Visual Studio*" OR CommandLine="*\\Microsoft SDK*" OR CommandLine="*\\Windows Kit*" OR CommandLine="*\\Windows Resource Kit\\*"))) OR ((EventID="4688" CommandLine="*\\OleView.exe") NOT (EventID="4688" (CommandLine="*\\Microsoft Visual Studio*" OR CommandLine="*\\Microsoft SDK*" OR CommandLine="*\\Windows Kit*" OR CommandLine="*\\Windows Resource Kit\\*" OR CommandLine="*\\Microsoft.NET\\*")))

Executables Started in Suspicious Folder
	
	(EventID="1" (Image="C:\\PerfLogs\\*" OR Image="C:\\$Recycle.bin\\*" OR Image="C:\\Intel\\Logs\\*" OR Image="C:\\Users\\Default\\*" OR Image="C:\\Users\\Public\\*" OR Image="C:\\Users\\NetworkService\\*" OR Image="C:\\Windows\\Fonts\\*" OR Image="C:\\Windows\\Debug\\*" OR Image="C:\\Windows\\Media\\*" OR Image="C:\\Windows\\Help\\*" OR Image="C:\\Windows\\addins\\*" OR Image="C:\\Windows\\repair\\*" OR Image="C:\\Windows\\security\\*" OR Image="*\\RSA\\MachineKeys\\*" OR Image="C:\\Windows\\system32\\config\\systemprofile\\*"))

Execution in Non-Executable Folder
	
	(EventID="1" (Image="*\\$Recycle.bin" OR Image="*\\Users\\All Users\\*" OR Image="*\\Users\\Default\\*" OR Image="*\\Users\\Public\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\config\\systemprofile\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*"))

Execution in Webserver Root Folder
	
	(EventID="1" (Image="*\\wwwroot\\*" OR Image="*\\wmpub\\*" OR Image="*\\htdocs\\*")) NOT ((Image="*bin\\*" OR Image="*\\Tools\\*" OR Image="*\\SMSComponent\\*") (ParentImage="*\\services.exe"))

Exploit for CVE-2015-1641
	
	(EventID="1" ParentImage="*\\WINWORD.EXE" Image="*\\MicroScMgmt.exe ")

Exploit for CVE-2017-0261
	
	(EventID="1" ParentImage="*\\WINWORD.EXE" Image="*\\FLTLDR.exe*")

Exploit for CVE-2017-8759
	
	(EventID="1" ParentImage="*\\WINWORD.EXE" Image="*\\csc.exe")

Exploit Framework User Agent
	
	((UserAgent="Internet Explorer *" OR UserAgent="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; InfoPath.2)" OR UserAgent="Mozilla/4.0 (compatible; Metasploit RSPEC)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SIMBAR={7DB0F6DE-8DE7-4841-9084-28FA914B0F2E}; SLCC1; .N" OR UserAgent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" OR UserAgent="Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13" OR UserAgent="Mozilla/5.0" OR UserAgent="Mozilla/4.0 (compatible; SPIPE/1.0" OR UserAgent="Mozilla/5.0 (Windows NT 6.3; rv:39.0) Gecko/20100101 Firefox/35.0" OR UserAgent="Sametime Community Agent" OR UserAgent="X-FORWARDED-FOR" OR UserAgent="DotDotPwn v2.1" OR UserAgent="SIPDROID" OR UserAgent="*wordpress hash grabber*" OR UserAgent="*exploit*"))

Fireball Archer Install
	
	(EventID="1" CommandLine="*\\rundll32.exe *,InstallArcherSvc")

Flash Player Update from Suspicious Location
	
	((cs-uri-query="*/install_flash_player.exe" OR cs-uri-query="*/flash_install.php*")) NOT (cs-uri-query="*.adobe.com/*")

FlawedAmmyy RAT Detection
	
	(EventID="1" (file_hash="18436342cab7f1d078354e86cb749b1de388dcb4d1e22c959de91619947dfd63" OR file_hash="d82ca606007be9c988a5f961315c3eed1b12725c6a39aa13888e693dc3b9a975" OR file_hash="8903d514549aa9568c7fea0123758b954b9703c301b5e4941acb33cccd0d7c57" OR file_hash="2b53466eebd2c65f81004c567df9025ce68017241e421abcf33799bd3e827900" OR file_hash="0d100ff26a764c65f283742b9ec9014f4fd64df4f1e586b57f3cdce6eadeedcd" OR file_hash="9a7fb98dd4c83f1b4995b9b358fa236969e826e4cb84f63f4f9881387bc88ccf" OR file_hash="b0ad80bf5e28e81ad8a7b13eec9c5c206f412870814d492b78f7ce4d574413d2" OR file_hash="cafa3466e422dd4256ff20336c1a032bbf6e915f410145b42b453e2646004541" OR file_hash="404d3d65430fbbdadedb206a29e6158c66a8efa2edccb7e648c1dd017de47572" OR file_hash="cc0205845562e017ff8b3aafb17de167529d113fc680e07ee9d8753d81487b2f" OR file_hash="790e7dc8b2544f1c76ff95e56315fee7ef3fe623975c37d049cc47f82f18e4f2" OR file_hash="2d19c42f753dcee5b46344f352c11a1c645f0b77e205c218c985bd1eb988c7ce" OR file_hash="6e701670350b4aea3d2ead4b929317b0a6d835aa4c0331b25d65ecbfbf8cb500" OR file_hash="3cd39abdbeb171d713ee8367ab60909f72da865dbb3bd858e4f6d31fd9c930d0" OR file_hash="1f5d31d41ebb417d161bc49d1c50533fcbff523bb583883b10b14974a3de8984" OR file_hash="6877ac35a3085d6c10fa48655cf9c2399bd96c3924273515eaf89b511bbe356a" OR file_hash="059c0588902be3e8a5d747df9e91f65cc50d908540bdeb08acf15242cc9a25b5" OR file_hash="c8b202e5a737b8b5902e852de730dbd170893f146ab9bbc9c06b0d93a7625e85" OR file_hash="927fa5fea13f8f3c28e307ffea127fb3511b32024349b39bbaee63fac8dcded7" OR file_hash="6048a55de1350238dfc0dd6ebed12ddfeb0a1f3788c1dc772801170756bf15c7" OR file_hash="adfdead4419c134f0ab2951f22cfd4d5a1d83c0abfe328ae456321fccf241eb6" OR file_hash="022f662903c6626fb81e844f7761f6f1cbaa6339e391468b5fbfb6d0a1ebf8cb" OR file_hash="3f5f5050adcf0d0894db64940299ac07994c4501b361dce179e3d45d9d155adf" OR file_hash="cafa3466e422dd4256ff20336c1a032bbf6e915f410145b42b453e2646004541"))

FlawedAmmyy RAT Detection (Proxy)
	
	((Request Url="http://chimachinenow.com" OR Request Url="http://highlandfamily.org" OR Request Url="http://intra.cfecgcaquitaine.com" OR Request Url="http://motifahsap.com" OR Request Url="http://sittalhaphedver.com" OR Request Url="http://wassronledorhad.in" OR Request Url="http://balzantruck.com" OR Request Url="http://185.176.221.54"))

Hack Tool User Agent
	
	((UserAgent="*(hydra)*" OR UserAgent="* arachni/*" OR UserAgent="* BFAC *" OR UserAgent="* brutus *" OR UserAgent="* cgichk *" OR UserAgent="*core-project/1.0*" OR UserAgent="* crimscanner/*" OR UserAgent="*datacha0s*" OR UserAgent="*dirbuster*" OR UserAgent="*domino hunter*" OR UserAgent="*dotdotpwn*" OR UserAgent="FHScan Core" OR UserAgent="*floodgate*" OR UserAgent="*get-minimal*" OR UserAgent="*gootkit auto-rooter scanner*" OR UserAgent="*grendel-scan*" OR UserAgent="* inspath *" OR UserAgent="*internet ninja*" OR UserAgent="*jaascois*" OR UserAgent="* zmeu *" OR UserAgent="*masscan*" OR UserAgent="* metis *" OR UserAgent="*morfeus fucking scanner*" OR UserAgent="*n-stealth*" OR UserAgent="*nsauditor*" OR UserAgent="*pmafind*" OR UserAgent="*security scan*" OR UserAgent="*springenwerk*" OR UserAgent="*teh forest lobster*" OR UserAgent="*toata dragostea*" OR UserAgent="* vega/*" OR UserAgent="*voideye*" OR UserAgent="*webshag*" OR UserAgent="*webvulnscan*" OR UserAgent="* whcc/*" OR UserAgent="* Havij" OR UserAgent="*absinthe*" OR UserAgent="*bsqlbf*" OR UserAgent="*mysqloit*" OR UserAgent="*pangolin*" OR UserAgent="*sql power injector*" OR UserAgent="*sqlmap*" OR UserAgent="*sqlninja*" OR UserAgent="*uil2pn*" OR UserAgent="ruler"))

Hacktool Use
	
	((EventID="4776" OR EventID="4624" OR EventID="4625") WorkstationName="RULER")

HIDDEN COBRA RAT/Worm
	
	(EventID="1" (file_hash="4731cbaee7aca37b596e38690160a749" OR file_hash="80fac6361184a3e24b33f6acb8688a6b7276b0f2" OR file_hash="077d9e0e12357d27f7f0c336239e961a7049971446f7a3f10268d9439ef67885" OR file_hash="4613f51087f01715bf9132c704aea2c2" OR file_hash="6b1ddf0e63e04146d68cd33b0e18e668b29035c4" OR file_hash="a1c483b0ee740291b91b11e18dd05f0a460127acfc19d47b446d11cd0e26d717" OR file_hash="e86c2f4fc88918246bf697b6a404c3ea" OR file_hash="9b7609349a4b9128b9db8f11ac1c77728258862c" OR file_hash="ea46ed5aed900cd9f01156a1cd446cbb3e10191f9f980e9f710ea1c20440c781" OR file_hash="298775b04a166ff4b8fbd3609e716945" OR file_hash="2e0f666831f64d7383a11b444e2c16b38231f481" OR file_hash="fe7d35d19af5f5ae2939457a06868754b8bdd022e1ff5bdbe4e7c135c48f9a16")) OR (EventID="1" (CommandLine="cmd.exe /q /c net share adnim$=%SystemRoot%" OR CommandLine="cmd.exe /q /c net share adnim$=%%SystemRoot%% /GRANT:%s,FULL" OR CommandLine="cmd.exe /q /c net share adnim$ /delete" OR CommandLine="cmd.exe /q /c net share adnim$=%SystemRoot% /GRANT:Administrator,FULL" OR CommandLine="cmd.exe /q /c net share adnim$=%SystemRoot%" OR CommandLine="cmd.exe /q /c net share adnim$=%%SystemRoot%% /GRANT:%s,FULL"))

Interactive Logon to Server Systems
	
	((EventID="528" OR EventID="529" OR EventID="4624" OR EventID="4625") LogonType="2" (ComputerName="%ServerSystems%" OR ComputerName="%DomainControllers%")) NOT (LogonProcessName="Advapi" ComputerName="%Workstations%")

InvisiMole SpyWare Detector
	
	(EventID="1" (file_hash="5EE6E0410052029EAFA10D1669AE3AA04B508BF9" OR file_hash="2FCC87AB226F4A1CC713B13A12421468C82CD586" OR file_hash="B6BA65A48FFEB800C29822265190B8EAEA3935B1" OR file_hash="C8C4B6BCB4B583BA69663EC3AED8E1E01F310F9F" OR file_hash="A5A20BC333F22FD89C34A532680173CBCD287FF8")) OR (EventID="13" (TargetObject="HKEY_CURRENT_USER\\Software\\Microsoft\\IE\\Cache") (keywords="Index")) OR (EventID="13" (TargetObject="HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Console" OR TargetObject="HKEY_CURRENT_USER\\Software\\Microsoft\\Direct3D") (keywords="Settings" OR keywords="Type")) OR (EventID="13" (TargetObject="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\OLE" OR TargetObject="HKEY_CURRENT_USER\\Software\\Microsoft\\Direct3D") (keywords="Common" OR keywords="Current" OR keywords="ENC" OR keywords="FFLT" OR keywords="Flag1" OR keywords="FlagLF" OR keywords="FlagLF2" OR keywords="IfData" OR keywords="INFO" OR keywords="InstallA" OR keywords="InstallB" OR keywords="LegacyImpersonationNumber" OR keywords="LM" OR keywords="MachineAccessStateData" OR keywords="MachineState*" OR keywords="RPT" OR keywords="SP2" OR keywords="SP3" OR keywords="SettingsMC" OR keywords="SettingsSR1" OR keywords="SettingsSR2") EventType="SetValue")

Java Running with Remote Debugging
	
	(EventID="1" CommandLine="*transport=dt_socket,address=*") NOT (CommandLine="*address=127.0.0.1*" OR CommandLine="*address=localhost*")

Kerberos Manipulation
	
	((EventID="675" OR EventID="4768" OR EventID="4769" OR EventID="4771") (FailureCode="0x9" OR FailureCode="0xA" OR FailureCode="0xB" OR FailureCode="0xF" OR FailureCode="0x10" OR FailureCode="0x11" OR FailureCode="0x13" OR FailureCode="0x14" OR FailureCode="0x1A" OR FailureCode="0x1F" OR FailureCode="0x21" OR FailureCode="0x22" OR FailureCode="0x23" OR FailureCode="0x24" OR FailureCode="0x26" OR FailureCode="0x27" OR FailureCode="0x28" OR FailureCode="0x29" OR FailureCode="0x2C" OR FailureCode="0x2D" OR FailureCode="0x2E" OR FailureCode="0x2F" OR FailureCode="0x31" OR FailureCode="0x32" OR FailureCode="0x3E" OR FailureCode="0x3F" OR FailureCode="0x40" OR FailureCode="0x41" OR FailureCode="0x43" OR FailureCode="0x44"))

klist purge
	
	(EventID="1" CommandLine="klist*purge")

List RDP Connections History Unload
	
	(EventID="1" (CommandLine="reg.exe*NTUSER.DAT"))

Locky Ransomware C2/Download/Payment Communication
	
	((dst="115.29.247.219" OR dst="211.149.241.201" OR dst="176.114.0.20" OR dst="162.144.211.154" OR dst="202.133.118.222" OR dst="194.28.49.140" OR dst="216.110.144.152" OR dst="209.126.99.6" OR dst="193.201.225.124" OR dst="176.121.14.95" OR dst="138.128.171.35" OR dst="178.62.242.179" OR dst="92.53.120.233" OR dst="200.7.102.105" OR dst="188.127.239.53" OR dst="62.75.162.77" OR dst="218.232.104.232" OR dst="210.196.232.211" OR dst="104.27.149.238" OR dst="37.59.51.53" OR dst="211.40.221.90" OR dst="207.45.186.214" OR dst="122.114.99.100" OR dst="97.74.215.147" OR dst="212.85.104.64" OR dst="89.149.4.195" OR dst="123.30.181.207" OR dst="37.187.143.115" OR dst="212.23.79.123" OR dst="195.228.152.23" OR dst="188.94.74.76" OR dst="172.246.156.150" OR dst="180.71.58.101" OR dst="119.29.99.214" OR dst="208.56.45.17" OR dst="203.98.84.123" OR dst="211.149.250.179" OR dst="120.39.243.225" OR dst="202.125.36.106" OR dst="85.13.128.34" OR dst="107.180.51.106" OR dst="103.63.26.159" OR dst="119.29.9.237" OR dst="216.249.101.162" OR dst="31.202.128.199" OR dst="162.144.116.161" OR dst="222.124.206.41" OR dst="199.101.51.76" OR dst="107.180.1.210" OR dst="116.255.193.108" OR dst="91.142.90.46" OR dst="95.211.144.65" OR dst="185.87.184.130" OR dst="120.25.161.125" OR dst="94.231.77.230" OR dst="185.25.149.13" OR dst="139.224.165.195" OR dst="69.195.129.70" OR dst="93.185.104.25" OR dst="37.153.89.141" OR dst="108.163.209.27" OR dst="194.1.239.152" OR dst="51.255.107.20" OR dst="194.28.87.26" OR dst="185.17.41.83" OR dst="176.103.56.119" OR dst="109.234.35.230" OR dst="192.186.241.104" OR dst="108.168.206.100" OR dst="208.100.26.234")) OR ((src="115.29.247.219" OR src="211.149.241.201" OR src="176.114.0.20" OR src="162.144.211.154" OR src="202.133.118.222" OR src="194.28.49.140" OR src="216.110.144.152" OR src="209.126.99.6" OR src="193.201.225.124" OR src="176.121.14.95" OR src="138.128.171.35" OR src="178.62.242.179" OR src="92.53.120.233" OR src="200.7.102.105" OR src="188.127.239.53" OR src="62.75.162.77" OR src="218.232.104.232" OR src="210.196.232.211" OR src="104.27.149.238" OR src="37.59.51.53" OR src="211.40.221.90" OR src="207.45.186.214" OR src="122.114.99.100" OR src="97.74.215.147" OR src="212.85.104.64" OR src="89.149.4.195" OR src="123.30.181.207" OR src="37.187.143.115" OR src="212.23.79.123" OR src="195.228.152.23" OR src="188.94.74.76" OR src="172.246.156.150" OR src="180.71.58.101" OR src="119.29.99.214" OR src="208.56.45.17" OR src="203.98.84.123" OR src="211.149.250.179" OR src="120.39.243.225" OR src="202.125.36.106" OR src="85.13.128.34" OR src="107.180.51.106" OR src="103.63.26.159" OR src="119.29.9.237" OR src="216.249.101.162" OR src="31.202.128.199" OR src="162.144.116.161" OR src="222.124.206.41" OR src="199.101.51.76" OR src="107.180.1.210" OR src="116.255.193.108" OR src="91.142.90.46" OR src="95.211.144.65" OR src="185.87.184.130" OR src="120.25.161.125" OR src="94.231.77.230" OR src="185.25.149.13" OR src="139.224.165.195" OR src="69.195.129.70" OR src="93.185.104.25" OR src="37.153.89.141" OR src="108.163.209.27" OR src="194.1.239.152" OR src="51.255.107.20" OR src="194.28.87.26" OR src="185.17.41.83" OR src="176.103.56.119" OR src="109.234.35.230" OR src="192.186.241.104" OR src="108.168.206.100" OR src="208.100.26.234"))

Lojack Double-Agent Communication
	
	((r-dns="sysanalyticweb.com" OR r-dns="elaxo.org" OR r-dns="ikmtrust.com" OR r-dns="lxwo.org"))

LokiBot Trojan Detector
	
	(EventID="1" (CommandLine="GET /bobby/" OR CommandLine="POST /bobby/Panel/")) OR ((file_hash="3C4BE617FDA78DA05B38F4EE52121E99" OR file_hash="7FB5A88768D7ECE242DBD4B30EDEFF0C" OR file_hash="14A4DFFE0105A7DEF2A1EFF32899A9AC" OR file_hash="E69245E9685CB204105E69C424F304CC" OR file_hash="75CCD03BB4934490A9F599A15381F43D" OR file_hash="68BEFE15006189CE8215371935F8E720" OR file_hash="05869152534B238D25051F7718FDB382" OR file_hash="3DFA31D85482009479FEAFD5AF7E818A"))

Malicious Named Pipe
	
	((EventID="17" OR EventID="18") (PipeName="\\isapi_http" OR PipeName="\\isapi_dg" OR PipeName="\\isapi_dg2" OR PipeName="\\sdlrpc" OR PipeName="\\ahexec" OR PipeName="\\winsession" OR PipeName="\\lsassw" OR PipeName="\\46a676ab7f179e511e30dd2dc41bd388" OR PipeName="\\9f81f59bc58452127884ce513865ed20" OR PipeName="\\e710f28d59aa529d6792ca6ff0ca1b34" OR PipeName="\\rpchlp_3" OR PipeName="\\NamePipe_MoreWindows" OR PipeName="\\pcheap_reuse" OR PipeName="\\NamePipe_MoreWindows"))

Malicious PowerShell Commandlets
	
	("Invoke-DllInjection" OR "Invoke-Shellcode" OR "Invoke-WmiCommand" OR "Get-GPPPassword" OR "Get-Keystrokes" OR "Get-TimedScreenshot" OR "Get-VaultCredential" OR "Invoke-CredentialInjection" OR "Invoke-Mimikatz" OR "Invoke-NinjaCopy" OR "Invoke-TokenManipulation" OR "Out-Minidump" OR "VolumeShadowCopyTools" OR "Invoke-ReflectivePEInjection" OR "Invoke-UserHunter" OR "Find-GPOLocation" OR "Invoke-ACLScanner" OR "Invoke-DowngradeAccount" OR "Get-ServiceUnquoted" OR "Get-ServiceFilePermission" OR "Get-ServicePermission" OR "Invoke-ServiceAbuse" OR "Install-ServiceBinary" OR "Get-RegAutoLogon" OR "Get-VulnAutoRun" OR "Get-VulnSchTask" OR "Get-UnattendedInstallFile" OR "Get-WebConfig" OR "Get-ApplicationHost" OR "Get-RegAlwaysInstallElevated" OR "Get-Unconstrained" OR "Add-RegBackdoor" OR "Add-ScrnSaveBackdoor" OR "Gupt-Backdoor" OR "Invoke-ADSBackdoor" OR "Enabled-DuplicateToken" OR "Invoke-PsUaCme" OR "Remove-Update" OR "Check-VM" OR "Get-LSASecret" OR "Get-PassHashes" OR "Invoke-Mimikatz" OR "Show-TargetScreen" OR "Port-Scan" OR "Invoke-PoshRatHttp" OR "Invoke-PowerShellTCP" OR "Invoke-PowerShellWMI" OR "Add-Exfiltration" OR "Add-Persistence" OR "Do-Exfiltration" OR "Start-CaptureServer" OR "Invoke-DllInjection" OR "Invoke-ReflectivePEInjection" OR "Invoke-ShellCode" OR "Get-ChromeDump" OR "Get-ClipboardContents" OR "Get-FoxDump" OR "Get-IndexedItem" OR "Get-Keystrokes" OR "Get-Screenshot" OR "Invoke-Inveigh" OR "Invoke-NetRipper" OR "Invoke-NinjaCopy" OR "Out-Minidump" OR "Invoke-EgressCheck" OR "Invoke-PostExfil" OR "Invoke-PSInject" OR "Invoke-RunAs" OR "MailRaider" OR "New-HoneyHash" OR "Set-MacAttribute" OR "Get-VaultCredential" OR "Invoke-DCSync" OR "Invoke-Mimikatz" OR "Invoke-PowerDump" OR "Invoke-TokenManipulation" OR "Exploit-Jboss" OR "Invoke-ThunderStruck" OR "Invoke-VoiceTroll" OR "Set-Wallpaper" OR "Invoke-InveighRelay" OR "Invoke-PsExec" OR "Invoke-SSHCommand" OR "Get-SecurityPackages" OR "Install-SSP" OR "Invoke-BackdoorLNK" OR "PowerBreach" OR "Get-GPPPassword" OR "Get-SiteListPassword" OR "Get-System" OR "Invoke-BypassUAC" OR "Invoke-Tater" OR "Invoke-WScriptBypassUAC" OR "PowerUp" OR "PowerView" OR "Get-RickAstley" OR "Find-Fruit" OR "HTTP-Login" OR "Find-TrustedDocuments" OR "Invoke-Paranoia" OR "Invoke-WinEnum" OR "Invoke-ARPScan" OR "Invoke-PortScan" OR "Invoke-ReverseDNSLookup" OR "Invoke-SMBScanner" OR "Invoke-Mimikittenz")

Malicious PowerShell Commandlets
	
	("AdjustTokenPrivileges" OR "IMAGE_NT_OPTIONAL_HDR64_MAGIC" OR "Management.Automation.RuntimeException" OR "Microsoft.Win32.UnsafeNativeMethods" OR "ReadProcessMemory.Invoke" OR "Runtime.InteropServices" OR "SE_PRIVILEGE_ENABLED" OR "System.Security.Cryptography" OR "System.Runtime.InteropServices" OR "LSA_UNICODE_STRING" OR "MiniDumpWriteDump" OR "PAGE_EXECUTE_READ" OR "Net.Sockets.SocketFlags" OR "Reflection.Assembly" OR "SECURITY_DELEGATION" OR "TOKEN_ADJUST_PRIVILEGES" OR "TOKEN_ALL_ACCESS" OR "TOKEN_ASSIGN_PRIMARY" OR "TOKEN_DUPLICATE" OR "TOKEN_ELEVATION" OR "TOKEN_IMPERSONATE" OR "TOKEN_INFORMATION_CLASS" OR "TOKEN_PRIVILEGES" OR "TOKEN_QUERY" OR "Metasploit" OR "Mimikatz")

Malicious Service Install
	
	(((EventID="7045" OR EventID="4697")) ("WCE SERVICE" OR "WCESERVICE" OR "DumpSvc")) OR (EventID="16" HiveName="*\\AppData\\Local\\Temp\\SAM*.dmp")

Malicious Service Installations
	
	(EventID="7045") (((ServiceName="WCESERVICE" OR ServiceName="WCE SERVICE")) OR (ServiceFileName="*\\PAExec*") OR (ServiceFileName="winexesvc.exe*") OR (ServiceFileName="*\\DumpSvc.exe") OR (ServiceName="mssecsvc2.0") OR (ServiceFileName="* net user *") OR ((ServiceName="pwdump*" OR ServiceName="gsecdump*" OR ServiceName="cachedump*")))

Malware Shellcode in Verclsid Target Process
	
	(EventID="10" TargetImage="*\\verclsid.exe" GrantedAccess="0x1FFFFF") ((CallTrace="*|UNKNOWN(*VBE7.DLL*") OR (SourceImage="*\\Microsoft Office\\*" CallTrace="*|UNKNOWN*"))

Malware User Agent
	
	((UserAgent="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Chrome /53.0" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR  1.1.4322)" OR UserAgent="HttpBrowser/1.0" OR UserAgent="*<|>*" OR UserAgent="nsis_inetc (mozilla)" OR UserAgent="Wget/1.9+cvs-stable (Red Hat modified)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" OR UserAgent="*zeroup*" OR UserAgent="Mozilla/5.0 (Windows NT 5.1 ; v.*" OR UserAgent="* adlib/*" OR UserAgent="* tiny" OR UserAgent="* BGroom *" OR UserAgent="* changhuatong" OR UserAgent="* CholTBAgent" OR UserAgent="Mozilla/5.0 WinInet" OR UserAgent="RookIE/1.0" OR UserAgent="M" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)" OR UserAgent="Mozilla/4.0 (compatible;MSIE 7.0;Windows NT 6.0)" OR UserAgent="backdoorbot" OR UserAgent="Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30731)" OR UserAgent="Opera/8.81 (Windows NT 6.0; U; en)" OR UserAgent="Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.1 (.NET CLR 3.5.30729)" OR UserAgent="Opera" OR UserAgent="Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)" OR UserAgent="MSIE" OR UserAgent="*(Charon; Inferno)" OR UserAgent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)" OR UserAgent="* pxyscand*" OR UserAgent="* asd" OR UserAgent="* mdms" OR UserAgent="sample" OR UserAgent="nocase" OR UserAgent="Moxilla" OR UserAgent="Win32 *" OR UserAgent="*Microsoft Internet Explorer*" OR UserAgent="agent *" OR UserAgent="AutoIt" OR UserAgent="IczelionDownLoad"))

Microsoft Binary Github Communication
	
	(EventID="3" DestinationHostname="*.github.com" Image="C:\\Windows\\*")

Microsoft Malware Protection Engine Crash
	
	((Source="Application Error" EventID="1000") OR (Source="Windows Error Reporting" EventID="1001")) ("MsMpEng.exe" OR "mpengine.dll")

Microsoft Office Product Spawning Windows Shell
	
	(EventID="1" (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.exe" OR ParentImage="*\\MSPUB.exe" OR ParentImage="*\\VISIO.exe" OR ParentImage="*\\OUTLOOK.EXE") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\scrcons.exe" OR Image="*\\schtasks.exe" OR Image="*\\regsvr32.exe" OR Image="*\\hh.exe" OR Image="*\\wmic.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\msiexec.exe"))

Microsoft Outlook Spawning Windows Shell
	
	(EventID="1" (ParentImage="*\\OUTLOOK.EXE") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\schtasks.exe"))

Mimikatz Detection LSASS Access
	
	(EventID="10" TargetImage="C:\\windows\\system32\\lsass.exe" GrantedAccess="0x1410")


Mimikatz Use
	
	("mimikatz" OR "mimilib" OR "<3 eo.oe" OR "eo.oe.kiwi" OR "privilege::debug" OR "sekurlsa::logonpasswords" OR "lsadump::sam" OR "mimidrv.sys")

MSHTA Spawning Windows Shell
	
	(EventID="1" ParentImage="*\\mshta.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\reg.exe" OR Image="*\\regsvr32.exe" OR Image="*\\BITSADMIN*")) NOT ((CommandLine="*/HP/HP*" OR CommandLine="*\\HP\\HP*"))

MuddyWater APT
	
	(EventID="1" (file_hash="4121db476b66241610985350b825b9f1680d0171ab01a52b5ffcb56481521e44" OR file_hash="a0abec361411cb11e01337939013bad1f54ad5865c73604a1b360d68ddfbd96a" OR file_hash="b2c10621c9c901f0f692cae0306baa840105231f35e6ec36e41b88eebd46df4c" OR file_hash="16bcb6cc38347a722bb7682799e9d9da40788e3ca15f29e46b475efe869d0a04")) OR (EventID="11")

Multiple Failed Logins with Different Accounts from Single Source System
	
	(pam_message="authentication failure" pam_user="*" pam_rhost="*") | stats count(pam_user) as val by pam_rhost | search val > 3

Multiple Failed Logins with Different Accounts from Single Source System
	
	"((EventID=""529"" OR EventID=""4625"") UserName=""*"" WorkstationName=""*"") | stats count(
	UserName) as val by WorkstationName | search val > 3
	
	(EventID=""4776"" UserName=""*"" Workstation=""*"") | stats count(UserName) as val by Workstation | search val > 3"

Multiple Modsecurity Blocks
	
	("mod_security: Access denied" OR "ModSecurity: Access denied" OR "mod_security-message: Access denied") | stats count() as val | search val > 6

Multiple suspicious Response Codes caused by Single Client
	
	((response="400" OR response="401" OR response="403" OR response="500")) | stats count() as val by clientip | search val > 10

Net.exe Execution
	
	(EventID="1" (Image="*\\net.exe" OR Image="*\\net1.exe") (CommandLine="* group*" OR CommandLine="* localgroup*" OR CommandLine="* user*" OR CommandLine="* view*" OR CommandLine="* share" OR CommandLine="* accounts*" OR CommandLine="* use*"))

Network Scans
	

	"(action=""denied"") | stats count(dst_port) as val by src_ip | search val > 10
	
	(action=""denied"") | stats count(dst_ip) as val by src_ip | search val > 10"

New RUN Key Pointing to Suspicious Folder
	
	(EventID="13" TargetObject="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*" (Details="C:\\Windows\\Temp\\*" OR Details="*\\AppData\\*" OR Details="C:\\$Recycle.bin\\*" OR Details="C:\\Temp\\*" OR Details="C:\\Users\\Public\\*" OR Details="C:\\Users\\Default\\*"))

NotPetya Ransomware Activity
	
	(EventID="1" Image="*\\fsutil.exe" CommandLine="* deletejournal *") OR (EventID="1" CommandLine="*\\AppData\\Local\\Temp\\* \\\\.\\pipe\\*") OR (EventID="1" Image="*\\wevtutil.exe" CommandLine="* cl *") OR (EventID="1" Image="*\\rundll32.exe" CommandLine="*.dat,#1") OR ("*\\perfc.dat*")

Office Macro Starts Cmd
	
	(EventID="1" (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE") Image="*\\cmd.exe")

OrangeWorm C2 Communication
	
	((dst="65.116.107.24" OR dst="13.44.61.126" OR dst="56.28.111.63" OR dst="118.71.138.69" OR dst="117.32.65.101" OR dst="18.25.62.70" OR dst="92.137.43.17" OR dst="33.25.72.21" OR dst="16.48.37.37" OR dst="91.29.51.11")) OR ((src="65.116.107.24" OR src="13.44.61.126" OR src="56.28.111.63" OR src="118.71.138.69" OR src="117.32.65.101" OR src="18.25.62.70" OR src="92.137.43.17" OR src="33.25.72.21" OR src="16.48.37.37" OR src="91.29.51.11"))

OrangeWorm Kwampirs service installation
	
	(EventID="7045" (ServiceName="WmiApSrvEx"))

Pandemic Registry Key
	
	(EventID="13" (TargetObject="\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\services\\null\\Instance*" OR TargetObject="\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\services\\null\\Instance*" OR TargetObject="\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\services\\null\\Instance*")) OR (EventID="1" Command="loaddll -a *")

Pass the Hash Activity
	
	(EventID="4624" LogonType="3" LogonProcessName="NtLmSsp" WorkstationName="%Workstations%" ComputerName="%Workstations%" OR EventID="4625" LogonType="3" LogonProcessName="NtLmSsp" WorkstationName="%Workstations%" ComputerName="%Workstations%") NOT (AccountName="ANONYMOUS LOGON")

Password Change on Directory Service Restore Mode (DSRM) Account
	
	(EventID="4794")

Password Dumper Activity on LSASS
	
	(EventID="4656" ProcessName="C:\\Windows\\System32\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN")

Password Dumper Remote Thread in LSASS
	
	(EventID="8" TargetImage="C:\\Windows\\System32\\lsass.exe" NOT StartModule="*")

Ping Hex IP
	
	(EventID="1" (CommandLine="*\\ping.exe 0x*" OR CommandLine="*\\ping 0x*"))


PowerShell called from an Executable Version Mismatch
	
	(EventID="400" (EngineVersion="2.*" OR EngineVersion="4.*" OR EngineVersion="5.*") HostVersion="3.*")

PowerShell Credential Prompt
	
	(EventID="4104") ("PromptForCredential")

PowerShell Downgrade Attack
	
	(EventID="400" EngineVersion="2.*") NOT (HostVersion="2.*")

PowerShell Download from URL
	
	(EventID="1" Image="*\\powershell.exe" (CommandLine="*new-object system.net.webclient).downloadstring(*" OR CommandLine="*new-object system.net.webclient).downloadfile(*"))

PowerShell Network Connections
	
	(EventID="3" Image="*\\powershell.exe") NOT ((DestinationIp="10.*" OR DestinationIp="192.168.*" OR DestinationIp="172.*" OR DestinationIp="127.0.0.1") DestinationIsIpv6="false" User="NT AUTHORITY\\SYSTEM")
PowerShell PSAttack
 	
 	
 	(EventID="4103") ("PS ATTACK!!!")

Processes created by MMC
	
	(EventID="1" ParentImage="*\\mmc.exe" Image="*\\cmd.exe") NOT (CommandLine="*\\RunCmd.cmd")

Program Executions in Suspicious Folders
	
	(type="SYSCALL" (exe="/tmp/*" OR exe="/var/www/*" OR exe="/usr/local/apache2/*" OR exe="/usr/local/httpd/*" OR exe="/var/apache/*" OR exe="/srv/www/*" OR exe="/home/httpd/html/*" OR exe="/var/lib/pgsql/data/*" OR exe="/usr/local/mysql/data/*" OR exe="/var/lib/mysql/*" OR exe="/var/vsftpd/*" OR exe="/etc/bind/*" OR exe="/var/named/*" OR exe="*/public_html/*"))

Ps.exe Renamed SysInternals Tool
	
	(EventID="1" CommandLine="ps.exe -accepteula")

PsExec Service Start
	
	(EventID="4688" CommandLine="C:\\Windows\\PSEXESVC.exe")

PsExec Tool Execution
	
	(EventID="7045" ServiceName="PSEXESVC" ServiceFileName="*\\PSEXESVC.exe") OR (EventID="7036" ServiceName="PSEXESVC") OR (EventID="1" Image="*\\PSEXESVC.exe" User="NT AUTHORITY\\SYSTEM")

Python SQL Exceptions
	
	("DataError" OR "IntegrityError" OR "ProgrammingError" OR "OperationalError")

QuarksPwDump Dump File
	
	(EventID="11" TargetFilename="*\\AppData\\Local\\Temp\\SAM-*.dmp*")

Rare Scheduled Task Creations
	
	(EventID="106") | stats count() as val by TaskName | search val < 5

Rare Schtasks Creations
	
	(EventID="4698") | stats count(TaskName) as val | search val < 5

Rare Service Installs
	
	(EventID="7045") | stats count(ServiceFileName) as val | search val < 5

Reconnaissance Activity
	
	(EventID="4661" ObjectType="SAM_USER" ObjectName="S-1-5-21-*-500" AccessMask="0x2d" OR EventID="4661" ObjectType="SAM_GROUP" ObjectName="S-1-5-21-*-512" AccessMask="0x2d")

Registry Persistence Mechanisms
	
	(EventID="13" (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\GlobalFlag" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\ReportingMode" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess") EventType="SetValue")

Regsvr32 Anomaly
	
	(EventID="1" Image="*\\regsvr32.exe" CommandLine="*\\Temp\\*") OR (EventID="1" Image="*\\regsvr32.exe" ParentImage="*\\powershell.exe") OR (EventID="1" Image="*\\regsvr32.exe" (CommandLine="*/i:http* scrobj.dll" OR CommandLine="*/i:ftp* scrobj.dll")) OR (EventID="1" Image="*\\wscript.exe" ParentImage="*\\regsvr32.exe") OR (EventID="1" Image="*\\EXCEL.EXE" CommandLine="*..\\..\\..\\Windows\\System32\\regsvr32.exe *")

Relevant Anti-Virus Event
	
	("HTool" OR "Hacktool" OR "ASP/Backdoor" OR "JSP/Backdoor" OR "PHP/Backdoor" OR "Backdoor.ASP" OR "Backdoor.JSP" OR "Backdoor.PHP" OR "Webshell" OR "Portscan" OR "Mimikatz" OR "WinCred" OR "PlugX" OR "Korplug" OR "Pwdump" OR "Chopper" OR "WmiExec" OR "Xscan" OR "Clearlog" OR "ASPXSpy") NOT ("Keygen" OR "Crack")

Relevant ClamAV Message
	
	("Trojan*FOUND" OR "VirTool*FOUND" OR "Webshell*FOUND" OR "Rootkit*FOUND" OR "Htran*FOUND")

Ruby on Rails framework exceptions
	
	("ActionController::InvalidAuthenticityToken" OR "ActionController::InvalidCrossOriginRequest" OR "ActionController::MethodNotAllowed" OR "ActionController::BadRequest" OR "ActionController::ParameterMissing")

Rundll32 Internet Connection
	
	(EventID="3" Image="*\\rundll32.exe") NOT ((DestinationIp="10.*" OR DestinationIp="192.168.*" OR DestinationIp="172.*"))

SAM Dump to AppData
	
	(EventID="16") ("*\\AppData\\Local\\Temp\\SAM-*.dmp *")

Scheduled Task Creation
	
	(EventID="1" Image="*\\schtasks.exe" CommandLine="* /create *") NOT (User="NT AUTHORITY\\SYSTEM")

Secure Deletion with Sdelete
	
	((EventID="4656" OR EventID="4663" OR EventID="4658") (ObjectName="*.AAA" OR ObjectName="*.ZZZ"))

Security Eventlog Cleared
	
	((EventID="517" OR EventID="1102"))

Shells Spawned by Web Servers
	
	(EventID="1" (ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe") (Image="*\\cmd.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\powershell.exe"))

Shellshock Expression
	
	("/\\(\\)\\s*\\t*\\{.*;\\s*\\}\\s*;/")

smbexec.py Service Installation
	
	(EventID="7045" ServiceName="BTOBTO" ServiceFileName="*\\execute.bat")

Sofacy - APT C2 Domain Communication
	
	((r-dns="myinvestgroup.com" OR r-dns="netmediaresources.com" OR r-dns="webviewres.net" OR r-dns="adfs.senate.group" OR r-dns="adfs-senate.email" OR r-dns="adfs-senate.services" OR r-dns="adfs.senate.qov.info" OR r-dns="chmail.ir.udelivered.tk" OR r-dns="webmail-ibsf.org" OR r-dns="fil-luge.com" OR r-dns="biathlovvorld.com" OR r-dns="mail-ibu.eu" OR r-dns="fisski.ca" OR r-dns="iihf.eu" OR r-dns="Cdnverify.net" OR r-dns="osce-press.com" OR r-dns="electronicfrontierfoundation.org" OR r-dns="baltichost.org" OR r-dns="checkmalware.org" OR r-dns="kavkazcentr.info" OR r-dns="login-osce.org" OR r-dns="malwarecheck.info" OR r-dns="n0vinite.com" OR r-dns="nato.nshq.in" OR r-dns="natoexhibitionff14.com" OR r-dns="novinitie.com" OR r-dns="poczta.mon.q0v.pl" OR r-dns="q0v.pl" OR r-dns="qov.hu.com" OR r-dns="rnil.am" OR r-dns="scanmalware.info" OR r-dns="smigroup-online.co.uk" OR r-dns="standartnevvs.com" OR r-dns="updatecenter.name" OR r-dns="securitypractic.com" OR r-dns="drivers-update.info" OR r-dns="nato-press.com"))

Spring framework exceptions
	
	("AccessDeniedException" OR "CsrfException" OR "InvalidCsrfTokenException" OR "MissingCsrfTokenException" OR "CookieTheftException" OR "InvalidCookieException" OR "RequestRejectedException")

SquiblyTwo
	
	(EventID="1" (Image="*\\wmic.exe") (CommandLine="wmic * *format:\\\"http*" OR CommandLine="wmic * /format:'http" OR CommandLine="wmic * /format:http*")) OR (EventID="1" (Imphash="1B1A3F43BF37B5BFE60751F2EE2F326E" OR Imphash="37777A96245A3C74EB217308F3546F4C" OR Imphash="9D87C9D67CE724033C0B40CC4CA1B206") (CommandLine="* *format:\\\"http*" OR CommandLine="* /format:'http" OR CommandLine="* /format:http*"))

StalinLocker Detector
	
	(EventID="13" (TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Stalin" OR TargetObject="HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Stalin")) OR (EventID="1" (Image="*\\fl.dat" OR Image="*\\stalin.exe" OR Image="*\\USSR_Anthem.mp3")) OR (EventID="1" (file_hash="853177d9a42fab0d8d62a190894de5c27ec203240df0d9e70154a675823adf04")) OR (EventID="11")

Sticky Key Like Backdoor Usage
	
	(EventID="1" (ParentImage="*\\winlogon.exe") (CommandLine="*\\cmd.exe sethc.exe *" OR CommandLine="*\\cmd.exe utilman.exe *" OR CommandLine="*\\cmd.exe osk.exe *" OR CommandLine="*\\cmd.exe Magnify.exe *" OR CommandLine="*\\cmd.exe Narrator.exe *" OR CommandLine="*\\cmd.exe DisplaySwitch.exe *")) OR (EventID="13" (TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator.exe\\Debugger" OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch.exe\\Debugger") EventType="SetValue")

StoneDrill Service Install
	
	(EventID="7045" ServiceName="NtsSrv" ServiceFileName="* LocalService")

Successful Overpass the Hash Attempt
	
	(EventID="4624" LogonType="9" LogonProcessName="seclogo" AuthenticationPackageName="Negotiate")

Suspicious Activity in Shell Commands
	
	("wget * - http* | perl" OR "wget * - http* | sh" OR "wget * - http* | bash" OR "python -m SimpleHTTPServer" OR "import pty; pty.spawn" OR "*wget *; chmod +x*" OR "*wget *; chmod 777 *" OR "*cd /tmp || cd /var/run || cd /mnt*" OR "stop;service iptables stop;" OR "stop;SuSEfirewall2 stop;" OR "chmod 777 2020" OR "\">>/etc/rc.local;" OR "wget -c *;chmod 777" OR "base64 -d /tmp/" OR " | base64 -d" OR "/bin/chmod u+s" OR "chmod +s /tmp/" OR "chmod u+s /tmp/" OR "/tmp/haxhax" OR "/tmp/ns_sploit" OR "nc -l -p " OR "cp /bin/ksh " OR "cp /bin/sh " OR " /tmp/*.b64 " OR "/tmp/ysocereal.jar")

Suspicious Certutil Command
	
	(EventID="1" (CommandLine="*\\certutil.exe * -decode *" OR CommandLine="*\\certutil.exe * -decodehex *" OR CommandLine="*\\certutil.exe *-urlcache* http*" OR CommandLine="*\\certutil.exe *-urlcache* ftp*" OR CommandLine="*\\certutil.exe *-URL*" OR CommandLine="*\\certutil.exe *-ping*"))

Suspicious Control Panel DLL Load
	
	(EventID="1" ParentImage="*\\System32\\control.exe" CommandLine="*\\rundll32.exe *") NOT (CommandLine="*Shell32.dll*")

Suspicious Driver Load from Temp
	
	(EventID="6" ImageLoaded="*\\Temp\\*")

Suspicious Failed Logon Reasons
	
	((EventID="4625" OR EventID="4776") (Status="3221225586" OR Status="3221225583" OR Status="3221225584" OR Status="3221226515" OR Status="3221225868"))

Suspicious Kerberos RC4 Ticket Encryption
	
	(EventID="4769" TicketOptions="0x40810000" TicketEncryptionType="0x17") NOT (ServiceName="$*")

Suspicious Log Entries
	
	("entered promiscuous mode" OR "Deactivating service" OR "Oversized packet received from" OR "imuxsock begins to drop messages")

Suspicious Named Error
	
	("* dropping source port zero packet from *" OR "* denied AXFR from *" OR "* exiting (due to fatal error)*")

Suspicious PowerShell Download
	
	("System.Net.WebClient).DownloadString(" OR "system.net.webclient).downloadfile(")

Suspicious PowerShell Invocation based on Parent Process
	
	(EventID="1" (ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe") (Image="*\\powershell.exe")) NOT (CurrentDirectory="*\\Health Service State\\*")

Suspicious PowerShell Invocations
	
	(" -nop -w hidden -c * [Convert]::FromBase64String" OR " -w hidden -noni -nop -c \"iex(New-Object" OR " -w hidden -ep bypass -Enc" OR "powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run" OR "bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download" OR "iex(New-Object Net.WebClient).Download")

Suspicious PowerShell Invocations - Generic
	
	(" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " - windowstyle hidden ") (" -noni " OR " -noninteractive ")

Suspicious PowerShell Parameter Substring
	
	(Image="*\\powershell.exe") (" -windowstyle h " OR " -windowstyl h" OR " -windowsty h" OR " -windowst h" OR " -windows h" OR " -windo h" OR " -wind h" OR " -win h" OR " -wi h" OR " -win h " OR " -win hi " OR " -win hid " OR " -win hidd " OR " -win hidde " OR " -NoPr " OR " -NoPro " OR " -NoProf " OR " -NoProfi " OR " -NoProfil " OR " -nonin " OR " -nonint " OR " -noninte " OR " -noninter " OR " -nonintera " OR " -noninterac " OR " -noninteract " OR " -noninteracti " OR " -noninteractiv " OR " -ec " OR " -encodedComman " OR " -encodedComma " OR " -encodedComm " OR " -encodedCom " OR " -encodedCo " OR " -encodedC " OR " -encoded " OR " -encode " OR " -encod " OR " -enco " OR " -en ")

Suspicious PowerShell ZIPing activity
	
	("Compress-Archive") OR ("Expand-Archive") OR ("Microsoft.PowerShell.Archive")

Suspicious Program Location with Network Connections
	
	(EventID="3" (Image="*\\ProgramData\\*" OR Image="*\\$Recycle.bin" OR Image="*\\Users\\All Users\\*" OR Image="*\\Users\\Default\\*" OR Image="*\\Users\\Public\\*" OR Image="C:\\Perflogs\\*" OR Image="*\\config\\systemprofile\\*" OR Image="*\\Windows\\Fonts\\*" OR Image="*\\Windows\\IME\\*" OR Image="*\\Windows\\addins\\*"))

Suspicious Reconnaissance Activity
	
	(EventID="1" (CommandLine="net group \"domain admins\" /domain" OR CommandLine="net localgroup administrators"))

Suspicious SQL Error Messages
	
	("quoted string not properly terminated" OR "You have an error in your SQL syntax" OR "Unclosed quotation mark" OR near "*"="syntax error" OR "SELECTs to the left and right of UNION do not have the same number of result columns")

Suspicious SSHD Error
	
	("*unexpected internal error*" OR "*unknown or unsupported key type*" OR "*invalid certificate signing key*" OR "*invalid elliptic curve value*" OR "*incorrect signature*" OR "*error in libcrypto*" OR "*unexpected bytes remain after decoding*" OR "*fatal: buffer_get_string: bad string*" OR "*Local: crc32 compensation attack*" OR "*bad client public DH value*" OR "*Corrupted MAC on input*")

Suspicious Svchost Process
	
	(EventID="1" Image="*\\svchost.exe") NOT (ParentImage="*\\services.exe")

Suspicious TSCON Start
	
	(EventID="1" User="NT AUTHORITY\\SYSTEM" Image="*\\tscon.exe")

Suspicious Typical Malware Back Connect Ports
	
	(EventID="3" (DestinationPort="4443" OR DestinationPort="2448" OR DestinationPort="8143" OR DestinationPort="1777" OR DestinationPort="1443" OR DestinationPort="243" OR DestinationPort="65535" OR DestinationPort="13506" OR DestinationPort="3360" OR DestinationPort="200" OR DestinationPort="198" OR DestinationPort="49180" OR DestinationPort="13507" OR DestinationPort="6625" OR DestinationPort="4444" OR DestinationPort="4438" OR DestinationPort="1904" OR DestinationPort="13505" OR DestinationPort="13504" OR DestinationPort="12102" OR DestinationPort="9631" OR DestinationPort="5445" OR DestinationPort="2443" OR DestinationPort="777" OR DestinationPort="13394" OR DestinationPort="13145" OR DestinationPort="12103" OR DestinationPort="5552" OR DestinationPort="3939" OR DestinationPort="3675" OR DestinationPort="666" OR DestinationPort="473" OR DestinationPort="5649" OR DestinationPort="4455" OR DestinationPort="4433" OR DestinationPort="1817" OR DestinationPort="100" OR DestinationPort="65520" OR DestinationPort="1960" OR DestinationPort="1515" OR DestinationPort="743" OR DestinationPort="700" OR DestinationPort="14154" OR DestinationPort="14103" OR DestinationPort="14102" OR DestinationPort="12322" OR DestinationPort="10101" OR DestinationPort="7210" OR DestinationPort="4040" OR DestinationPort="9943")) NOT (Image="*\\Program Files*")

Suspicious User Agent
	
	((UserAgent="user-agent" OR UserAgent="* (compatible;MSIE *" OR UserAgent="*.0;Windows NT *" OR UserAgent="Mozilla/3.0 *" OR UserAgent="Mozilla/2.0 *" OR UserAgent="Mozilla/1.0 *" OR UserAgent="Mozilla *" OR UserAgent=" Mozilla/*" OR UserAgent="Mozila/*" OR UserAgent="_"))

Suspicious VSFTPD Error Messages
	
	("Connection refused: too many sessions for this address." OR "Connection refused: tcp_wrappers denial." OR "Bad HTTP verb." OR "port and pasv both active" OR "pasv and port both active" OR "Transfer done (but failed to open directory)." OR "Could not set file modification time." OR "bug: pid active in ptrace_sandbox_free" OR "PTRACE_SETOPTIONS failure" OR "weird status:" OR "couldn't handle sandbox event" OR "syscall * out of bounds" OR "syscall not permitted:" OR "syscall validate failed:" OR "Input line too long." OR "poor buffer accounting in str_netfd_alloc" OR "vsf_sysutil_read_loop")

Suspicious WMI execution
	
	(EventID="1" (Image="*\\wmic.exe") (CommandLine="*/NODE:*process call create *" OR CommandLine="* path AntiVirusProduct get *" OR CommandLine="* path FirewallProduct get *" OR CommandLine="* shadowcopy delete *"))

System File Execution Location Anomaly
	
	(EventID="1" (Image="*\\svchost.exe" OR Image="*\\rundll32.exe" OR Image="*\\services.exe" OR Image="*\\powershell.exe" OR Image="*\\regsvr32.exe" OR Image="*\\spoolsv.exe" OR Image="*\\lsass.exe" OR Image="*\\smss.exe" OR Image="*\\csrss.exe" OR Image="*\\conhost.exe")) NOT ((Image="*\\System32\\*" OR Image="*\\SysWow64\\*"))

Taskmgr as LOCAL_SYSTEM
	
	(EventID="1" User="NT AUTHORITY\\SYSTEM" Image="*\\taskmgr.exe")

Taskmgr as Parent
	
	(EventID="1" ParentImage="*\\taskmgr.exe") NOT ((Image="resmon.exe" OR Image="mmc.exe"))

Turla Group Named Pipes
	
	((EventID="17" OR EventID="18") (PipeName="\\atctl" OR PipeName="\\userpipe" OR PipeName="\\iehelper" OR PipeName="\\sdlrpc" OR PipeName="\\comnap"))

Turla Service Install
	
	(EventID="7045" (ServiceName="srservice" OR ServiceName="ipvpn" OR ServiceName="hkmsvc"))

UAC Bypass via Event Viewer
	
	(EventID="13" TargetObject="HKEY_USERS\\*\\mscfile\\shell\\open\\command") OR ((EventID="1" ParentImage="*\\eventvwr.exe") NOT (Image="*\\mmc.exe"))

UAC Bypass via sdclt
	
	(EventID="13" TargetObject="HKEY_USERS\\*\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand")

USB Device Plugged
	
	((EventID="2003" OR EventID="2100" OR EventID="2102"))

User Added to Local Administrators
	
	(EventID="4732" GroupName="Administrators") NOT (SubjectUserName="*$")

VPNFilter Destructive Malware detection
	
	((URL="photobucket.com/user/nikkireed11/library" OR URL="photobucket.com/user/nikkireed11/library" OR URL="photobucket.com/user/kmila302/library" OR URL="photobucket.com/user/lisabraun87/library" OR URL="photobucket.com/user/eva_green1/library" OR URL="photobucket.com/user/monicabelci4/library" OR URL="photobucket.com/user/katyperry45/library" OR URL="photobucket.com/user/saragray1/library" OR URL="photobucket.com/user/millerfred/library" OR URL="photobucket.com/user/jeniferaniston1/library" OR URL="photobucket.com/user/amandaseyfried1/library" OR URL="photobucket.com/user/suwe8/library" OR URL="photobucket.com/user/bob7301/library" OR URL="toknowall.com")) OR ((SourceIP="91.121.109.209" OR SourceIP="217.12.202.40" OR SourceIP="94.242.222.68" OR SourceIP="82.118.242.124" OR SourceIP="46.151.209.33" OR SourceIP="217.79.179.14" OR SourceIP="91.214.203.144" OR SourceIP="95.211.198.231" OR SourceIP="195.154.180.60" OR SourceIP="5.149.250.54" OR SourceIP="91.200.13.76" OR SourceIP="94.185.80.82" OR SourceIP="62.210.180.229" OR SourceIP="91.200.13.76" OR SourceIP="23.111.177.114" OR SourceIP="138.186.2.250" OR SourceIP="250.2.186.138" OR SourceIP="178.78.13.69" OR SourceIP="178.78.6.224" OR SourceIP="187.85.58.107" OR SourceIP="192.157.214.6" OR SourceIP="77.45.243.188" OR SourceIP="88.213.189.253" OR SourceIP="9.110.0.5")) OR ((DestinationIP="91.121.109.209" OR DestinationIP="217.12.202.40" OR DestinationIP="94.242.222.68" OR DestinationIP="82.118.242.124" OR DestinationIP="46.151.209.33" OR DestinationIP="217.79.179.14" OR DestinationIP="91.214.203.144" OR DestinationIP="95.211.198.231" OR DestinationIP="195.154.180.60" OR DestinationIP="5.149.250.54" OR DestinationIP="91.200.13.76" OR DestinationIP="94.185.80.82" OR DestinationIP="62.210.180.229" OR DestinationIP="91.200.13.76" OR DestinationIP="23.111.177.114" OR DestinationIP="138.186.2.250" OR DestinationIP="250.2.186.138" OR DestinationIP="178.78.13.69" OR DestinationIP="178.78.6.224" OR DestinationIP="187.85.58.107" OR DestinationIP="192.157.214.6" OR DestinationIP="77.45.243.188" OR DestinationIP="88.213.189.253" OR DestinationIP="9.110.0.5")) OR ("6b57dcnonk2edf5a.onion/bin32/update.php" OR "tljmmy4vmkqbdof4.onion/bin32/update.php" OR "zuh3vcyskd4gipkm.onion/bin32/update.php" OR "6b57dcnonk2edf5a.onion/bin32/update.php")

VPNFilter Destructive Malware detection
	
	((dst="91.121.109.209" OR dst="217.12.202.40" OR dst="94.242.222.68" OR dst="82.118.242.124" OR dst="46.151.209.33" OR dst="217.79.179.14" OR dst="91.214.203.144" OR dst="95.211.198.231" OR dst="195.154.180.60" OR dst="5.149.250.54" OR dst="91.200.13.76" OR dst="94.185.80.82" OR dst="62.210.180.229" OR dst="91.200.13.76" OR dst="23.111.177.114" OR dst="138.186.2.250" OR dst="250.2.186.138" OR dst="178.78.13.69" OR dst="178.78.6.224" OR dst="187.85.58.107" OR dst="192.157.214.6" OR dst="77.45.243.188" OR dst="88.213.189.253" OR dst="9.110.0.5")) OR ((src="91.121.109.209" OR src="217.12.202.40" OR src="94.242.222.68" OR src="82.118.242.124" OR src="46.151.209.33" OR src="217.79.179.14" OR src="91.214.203.144" OR src="95.211.198.231" OR src="195.154.180.60" OR src="5.149.250.54" OR src="91.200.13.76" OR src="94.185.80.82" OR src="62.210.180.229" OR src="91.200.13.76" OR src="23.111.177.114" OR src="138.186.2.250" OR src="250.2.186.138" OR src="178.78.13.69" OR src="178.78.6.224" OR src="187.85.58.107" OR src="192.157.214.6" OR src="77.45.243.188" OR src="88.213.189.253" OR src="9.110.0.5"))

VPNFilter Malware Detector (Hashes)
	
	(EventID="1" (file_hash="50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec" OR file_hash="0e0094d9bd396a6594da8e21911a3982cd737b445f591581560d766755097d92" OR file_hash="9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17" OR file_hash="d6097e942dd0fdc1fb28ec1814780e6ecc169ec6d24f9954e71954eedbc4c70e" OR file_hash="4b03288e9e44d214426a02327223b5e516b1ea29ce72fa25a2fcef9aa65c4b0b" OR file_hash="9eb6c779dbad1b717caa462d8e040852759436ed79cc2172692339bc62432387" OR file_hash="37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4" OR file_hash="776cb9a7a9f5afbaffdd4dbd052c6420030b2c7c3058c1455e0a79df0e6f7a1d" OR file_hash="8a20dc9538d639623878a3d3d18d88da8b635ea52e5e2d0c2cce4a8c5a703db1" OR file_hash="0649fda8888d701eb2f91e6e0a05a2e2be714f564497c44a3813082ef8ff250b" OR file_hash="f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344" OR file_hash="afd281639e26a717aead65b1886f98d6d6c258736016023b4e59de30b7348719"))

WannaCry Ransomware via Sysmon
	
	(EventID="1" (Image="*\\tasksche.exe" OR Image="*\\mssecsvc.exe" OR Image="*\\taskdl.exe" OR Image="*\\@WanaDecryptor@*" OR Image="*\\taskhsvc.exe" OR Image="*\\taskse.exe" OR Image="*\\111.exe" OR Image="*\\lhdfrgui.exe" OR Image="*\\diskpart.exe" OR Image="*\\linuxnew.exe" OR Image="*\\wannacry.exe")) OR (EventID="1" (CommandLine="*vssadmin delete shadows*" OR CommandLine="*icacls * /grant Everyone:F /T /C /Q*" OR CommandLine="*bcdedit /set {default} recoveryenabled no*" OR CommandLine="*wbadmin delete catalog -quiet*" OR CommandLine="*@Please_Read_Me@.txt*"))

WCE wceaux.dll Access
	
	((EventID="4656" OR EventID="4658" OR EventID="4660" OR EventID="4663") ObjectName="*\\wceaux.dll")

Weak Encryption Enabled and Kerberoast
	
	(EventID="4738") ("DES" OR "Preauth" OR "Encrypted") ("Enabled")

Webshell Detection by Keyword
	
	("=whoami" OR "=net%20user" OR "=cmd%20/c%20")

Webshell Detection With Command Line Keywords
	
	(EventID="1" (ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\httpd.exe") (CommandLine="whoami" OR CommandLine="net user" OR CommandLine="ping -n" OR CommandLine="systeminfo"))

Windows PowerShell User Agent
	
	(UserAgent="* WindowsPowerShell/*")

Windows PowerShell WebDav User Agent
	
	(UserAgent="Microsoft-WebDAV-MiniRedir/*")

Windows Shell Spawning Suspicious Program
	
	(EventID="1" (ParentImage="*\\mshta.exe" OR ParentImage="*\\powershell.exe" OR ParentImage="*\\cmd.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\cscript.exe" OR ParentImage="*\\wscript.exe" OR ParentImage="*\\wmiprvse.exe") (Image="*\\schtasks.exe" OR Image="*\\nslookup.exe" OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\mshta.exe"))

WMI Persistence
	
	((EventID="5861") ("ActiveScriptEventConsumer" OR "CommandLineEventConsumer" OR "CommandLineTemplate" OR "Binding EventFilter")) OR (EventID="5859")

WMI Persistence - Command Line Event Consumer
	
	(EventID="7" Image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" ImageLoaded="wbemcons.dll")

WMI Persistence - Script Event Consumer File Write
	
	(EventID="11" Image="C:\\WINDOWS\\system32\\wbem\\scrcons.exe")

WMIExec VBS Script
	
	(EventID="1" Image="*\\cscript.exe" CommandLine="*.vbs /shell *")

WScript or CScript Dropper
	
	(EventID="1" (Image="*\\wscript.exe" OR Image="*\\cscript.exe") (CommandLine="* C:\\Users\\*.jse *" OR CommandLine="* C:\\Users\\*.vbe *" OR CommandLine="* C:\\Users\\*.js *" OR CommandLine="* C:\\Users\\*.vba *" OR CommandLine="* C:\\Users\\*.vbs *" OR CommandLine="* C:\\ProgramData\\*.jse *" OR CommandLine="* C:\\ProgramData\\*.vbe *" OR CommandLine="* C:\\ProgramData\\*.js *" OR CommandLine="* C:\\ProgramData\\*.vba *" OR CommandLine="* C:\\ProgramData\\*.vbs *"))

WSF/JSE/JS/VBA/VBE File Execution
	
	(EventID="1" (Image="*\\wscript.exe" OR Image="*\\cscript.exe") (CommandLine="*.jse" OR CommandLine="*.vbe" OR CommandLine="*.js" OR CommandLine="*.vba"))

YiSpecter Malware Detection
	
	((r-dns="bb800.com" OR r-dns="ad.bb800.com" OR r-dns="down.bb800.com" OR r-dns="ty1.bb800.com" OR r-dns="iosnoico.bb800.com" OR r-dns="qvod.bb800.com" OR r-dns="qvios.od.bb800.com" OR r-dns="dp.bb800.com" OR r-dns="iosads.cdn.bb800.com"))

ZxShell Malware
	
	(EventID="1" (Command="rundll32.exe *,zxFunction*" OR Command="rundll32.exe *,RemoteDiskXXXXX"))
