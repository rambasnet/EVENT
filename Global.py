#-----------------------------------------------------------------------------
# Name:        Global.py
# Purpose:     
#
# Author:      Ram B. Basnet
#
# Created:     2009/10/10
# RCS-ID:      $Id: Global.py $
# Copyright:   (c) 2009
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

#The scanners to be used in consolidation reports.
#Only Nessus, Retina and Languard (case sensitive) are supported for now.
#You can remove but can't add new Scanners.
#Consolidate Host Level Vulnerabilites. Nmap doesn't give vulnerability info so, exclude it.
ConsolidationScanners = ['Nessus', 'Retina', 'Languard']

#Open Port level consolidation
#possibile scanner names Nessus, Retina, Languard, Nmap
ConsolidationPortScanners = ['Nessus', 'Retina', 'Languard', 'Nmap']

#Scanners that should be included in consolidations...only 4 are supported so far
#Do not add scanner; but you can remove one or more from the list
#Supported Scanners: Case sensitive, comma separated
#Nessus, Retina, Languard, Nmap 

ParseScanners = ['Nessus', 'Retina', 'Languard', 'Nmap']

#Do not need to modify it
ConsolidatedScannerName = "Consolidated"

"""
Different severity levels used in generating reports, list of integers from 0-3
3: High, 2: Medium, 1: Low, 0:Informational
Do not change the list!
"""
SeverityLevels = [1, 2, 3]

"""
True/False
If True, checks for each scanner report, if there's a duplicate IP already in the database.
Check if there are duplicate reports being parsed for each scanner.
True is recommended to be safe.
"""
CheckDuplicateIPs = True

"""
True/False
If True correlated the unique ports from the whole network with the top vulnerable
port report from DShield maintained by sans.org
"""
CorrelateDShieldTopPorts = True

"""
Searches for words or phrases in service or descriptions on reports by scanners
in ConsolidationScanners
You can try with list of any special keywords/phrases that you're interested in, but you may or may not get any
report depending on whether the query exists in service or descriptions fields
"""
SpecialSearchReports = ['Password', 'Share', 'Audit', 'SNMP', 'FTP', 'Anonymous FTP']


"""
If GenerateIndividualScannerDShieldTopTenReports is True then it will generate individual reports for each scanner
correlated with DShield's Top 10 Ports; set it False if you don't want those reports as Consolidated report gives you comprehensive
report for all scanners listed in 
True/False
"""
GenerateIndividualScannerDShieldTopTenReports = True

#If True, all reports and charts will be generated for each subnet in the network
GenerateSubnetWiseReportsAndCharts = True

#Generate reports with List of IPs With Special Keywords
#Do not change this if not sure
SpecialKeywords = ('Password Does Not Expire', 'User Never Logged On', 'Cannot Change Password')