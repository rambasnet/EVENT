#-----------------------------------------------------------------------------
# Name:        Reports.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/19
# Modified:    10/1/2009
# RCS-ID:      $Id: Reports.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string, re
import time, shutil
from SqliteDatabase import *
import os.path
import math, sys
import pylab
from Config import *
import Global

SubnetHostsSet = set()

SubnetPortsSet = {}

RetinaSubnets = []
LanguardSubnets = []
NmapSubnets = []

"""
        CREATE TABLE IF NOT EXISTS Navigation(
        `GrandParent` varchar(200),
        `Parent` varchar(200),
        `ReportGroup` varchar(200),
        `LinkText` varchar(200),
        `Link` varchar(300)
        );
"""
navigationQuery = 'insert into Navigation(GrandParent, Parent, ReportGroup, LinkText, Link) values (?,?,?,?,?)'

def IndividualVulnerabilityReport(scannerName, SeverityLevel, html=True, subnet=""):
    """Creates a report of all the ips/hosts based on high, medium, low severity"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
        
    portsTable = scannerName + "Ports"
    if subnet:
        query = "select IP, Port, Service, Description, CVEID from %s where (IP like '%s' and Severity=%s) order by IP;"%(portsTable, (subnet+"%"), SeverityLevel)
    else:
        query = "select IP, Port, Service, Description, CVEID from %s where Severity=%s order by IP;"%(portsTable, SeverityLevel)
        
    #print query
    rows = db.FetchAllRows(query)
    
    severity = ""
    if SeverityLevel == 3:
        severity = "High"
    elif SeverityLevel == 2:
        severity = "Medium"
    else:
        severity = "Low"
            
    global navigationQuery
    
    if html:
        
        fileName = '%s%sVulnerabilityReport.html'%(scannerName, severity)
        #query = 'insert into Navigation(GrandParent, Parent, ReportGroup, LinkText, Link) values (?,?,?,?,?)'
        if subnet:
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Reports"%scannerName, "%s Vulnerability"%severity, "./%s/%s"%(subnet, fileName)),]) 
            title = "%s %s Vulnerability Report in Subnet %s"%(scannerName, severity, subnet)
            dirPath = os.path.join(Config["OutputPath"], subnet)
            reportPath = os.path.join(dirPath, fileName)
            fout = open(reportPath, 'w')
        else:
            db.ExecuteMany(navigationQuery, [('Network', '', "%s Reports"%scannerName, "%s Vulnerability"%severity, "./%s"%fileName),]) 
            title = "%s %s Vulnerability Report"%(scannerName, severity)
            reportPath = os.path.join(Config["OutputPath"], fileName)
            fout = open(reportPath, 'w')
            
        
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <FONT face="Arial" size="5">
          
            <p>
        """%(title, title)
        htmlHeader += """
                <TABLE id="Table1" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center";>
                    <TD>IP
                    </TD>
                    <TD>
                        Port
                    </TD>
                    <TD>
                        Service
                    </TD>
                    <TD>
                        Description
                    </TD>
                    <TD>
                        CVE
                    </TD>
                </TR>
        """
        fout.write("%s\n"%htmlHeader)
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
    for row in rows:
        if html:
            fout.write('<TR>\n')
            fout.write('    <TD><b> %s </b></TD>\n'%(row[0]))
            port = row[1]
            if port == 100000:
                port = 'N/A'
            
            fout.write('    <TD> %s </TD>\n'%(port))
            fout.write('    <TD> %s </TD>\n'%(row[2]))
            fout.write('    <TD> %s </TD>\n'%(row[3].replace("=> ", "")))
            fout.write('    <TD> %s </TD>\n'%(row[4]))
            fout.write('</TR>\n')
    if html:
        fout.write(htmlFooter)
        
    fout.close()
    
    
def ConsolidatedVulnerabilitySummaryReport(SeverityLevel, html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    Summary = []
    
    scannersCount = len(Global.ConsolidationScanners)
    
    i = 0
    if subnet:
        noImgTag = '<img src="../../assets/no.gif" alt="No" />'
        #descriptions.append('%s\n'%imgSubnet)
    else:
        noImgTag = '<img src="assets/no.gif" alt="No" />'
                        
    for scanner in Global.ConsolidationScanners:
        PortsTable = scanner + "Ports"
        if subnet:
            query = "select IP, Port, Service, Description from %s where (Severity=%s and Port<>100000 and IP like '%s') order by IP;"%(PortsTable, SeverityLevel, (subnet+"%"))
        else:
            query = "select IP, Port, Service, Description from %s where (Severity=%s and Port<>100000) order by IP;"%(PortsTable, SeverityLevel)
            
        dbrows = db.FetchAllRows(query)
        #for each ip, port, service check if it already exists
        
        for dbrow in dbrows:
            exists = False
            ipPos = 0
            ipFound = False
            for row in Summary:
                #check if ip port and service all match
                #print 'row= ', row
                ipPos += 1
                if dbrow[0].lower().strip() == row[0].lower().strip():
                    ipFound = True
                    if dbrow[1] == row[1] and dbrow[2].lower().strip() == row[2].lower().strip():
                        exists = True
    
                        desc = dbrow[3].replace('<br/>', '')
                        if len(desc) > 100:
                            row[3][i] = "%s ..."%desc[:100]
                        else:
                            row[3][i] = "%s"%desc
                    break
                    
            if not exists:
                descriptions = []
                for sc in Global.ConsolidationScanners:
                    descriptions.append('%s\n'%noImgTag)

                desc = dbrow[3].replace('<br/>', '')
                if len(desc) > 100:
                    descriptions[i] = "%s ..."%desc[:100]
                else:
                    descriptions[i] = "%s"%desc
                #print descriptions
                newRow = [dbrow[0], dbrow[1], dbrow[2], descriptions]

                if ipFound:
                    Summary.insert(ipPos, newRow)
                else:
                    Summary.append(newRow)
        i += 1       
    
    severity = ""
    if SeverityLevel == 3:
        severity = "High"
    elif SeverityLevel == 2:
        severity = "Medium"
    else:
        severity = "Low"
    
    global navigationQuery
    if html:
        fileName = '%sConsolidatedVulnerabilitySummary.html'%(severity)
        
        if subnet:
            title = "%s Vulnerability Summary Report in Subnet %s"%(severity, subnet)
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "%s Vulnerability"%severity, "./%s/%s"%(subnet, fileName)),]) 
        else:
            title = "%s Vulnerability Summary Report"%(severity)
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "%s Vulnerability"%severity, "./%s"%(fileName)),]) 
             
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <FONT face="Arial" size="4">
              <p>
            Note: %s&nbsp; Not Reported
            </p>
            <p>
        """%(title, title, noImgTag)
        
        htmlHeader += """
                <TABLE id="Table1" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TD>
                        IP
                    </TD>
                    <TD>
                        Port
                    </TD>
                    <TD>
                        Service
                    </TD>
                    """
        for scanner in Global.ConsolidationScanners:
            htmlHeader += "<TD>%s</TD>"%scanner
        htmlHeader += "</TR>"
     
        fout.write("%s\n"%htmlHeader)
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        
    for row in Summary:
        if html:
            fout.write('<TR>\n')
            fout.write('    <TD><b> %s </b></TD>\n'%(row[0]))
            fout.write('    <TD> %s </TD>\n'%(row[1]))
            fout.write('    <TD> %s </TD>\n'%(row[2]))
            for des in row[3]:
                fout.write('    <TD> %s </TD>\n'%(des))
            fout.write('</TR>\n')
    if html:
        fout.write(htmlFooter)
        
    fout.close()    


def ConsolidatedUniquePortProtocolServiceReport(html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    global navigationQuery
    if html:
        fileName = 'ConsolidatedUniquePortProtocolServiceReport.html'
                 
        if subnet:
            title = "List of Unique Ports, Protocols, and Services in Subnet %s"%subnet
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "Unique Port Protocol Services", "./%s/%s"%(subnet, fileName)),]) 
        else:
            title = "Network-wide List of Unique Ports, Protocols, and Services"
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "Unique Port Protocol Services", "./%s"%(fileName)),]) 
            
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
        """%(title, title)
        fout.write(htmlHeader)
        #fout.write("""<P align="left"><STRONG><FONT face="Arial" size="4">Unique Ports:</FONT></STRONG><br/>""")
       
        fout.write("""<TABLE id="Table2" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor=" LightSteelBlue" style="font-size:small">""")
        fout.write("""<FONT face="Arial" size="2">""")
        if len(Global.ParseScanners) > 2:
            query = ""
            for scanner in Global.ParseScanners:
                if scanner.lower() != 'languard':
                    if query == "":
                        if subnet:
                            query += " select port from %sPorts where (port <> 100000 and IP like '%s')"%(scanner, (subnet + "%"))
                        else:
                            query += " select port from %sPorts where port <> 100000"%(scanner)
                    else:
                        if subnet:
                            query += " union select port from %sPorts where (port <> 100000 and IP like '%s')"%(scanner, (subnet + "%"))
                        else:
                            query += " union select port from %sPorts where port <> 100000"%scanner
                        
            query += " order by port "
            
        rows = db.FetchAllRows(query)
        Ports = []
        for port in rows:
            Ports.append(int(port[0]))
        
        if 'Languard' in Global.ParseScanners:
            if subnet:
                query = "select distinct port from LanguardPorts where (port <> 100000 and IP like '%s') order by port"%(subnet + "%")
            else:
                query = 'select distinct port from LanguardPorts where port <> 100000 order by port'
            ports = db.FetchAllRows(query)
            for port in ports:
                if int(port[0]) not in Ports:
                    Ports.append(int(port[0]))
                 
        DShieldTopPorts = []
        if Global.CorrelateDShieldTopPorts:
            fin = open(Config["DShieldTopPortsFile"], 'r')
            lines = fin.readlines()
            while lines:
                for line in lines:
                    if line.startswith("#") or line.startswith("port"):
                        continue
                    alist = line.split()
                    DShieldTopPorts.append(int(alist[0]))
                lines = fin.readlines()
            
        #print DShieldTopPorts
        col = 0
        Ports.sort()
        fout.write("""<FONT face="Arial" size="3">""")
        fout.write('<TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">')
        fout.write('<TH colspan=20>Unique Ports</TH></TR></font>\n')
        if Global.CorrelateDShieldTopPorts:
            fout.write("""<TR align="center"><TH colspan=20>Note: Red colored bold Port Number appears on the report at http://www.dshield.org/portreport.html on %s.<br/></th></tr>\n"""%Config["DShieldReportDate"])
        
        fout.write("<TR>\n")
        for port in Ports:
            if port in DShieldTopPorts:
                fout.write('<td><strong><font color="red">')
                fout.write(" %d </font></strong></td>"%port)
                
            else:
                fout.write("<td> %d </td>"%port)
                
            col += 1
            if col%20 == 0:
                fout.write("</tr>")
                
        fout.write("</table></font></p>\n")
        
        #fout.write("""<P align="left"><STRONG><FONT face="Arial" size="4">Unique Protocols:</FONT></STRONG><br/>""")
        #fout.write("""<FONT face="Arial" size="2">""")
        fout.write("""<TABLE id="Table2" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue">""")
        fout.write("""<FONT face="Arial" size="3">""")
        fout.write('<TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">')
        fout.write('<TH colspan=15>Unique Protocols</TH></TR></font>\n')
        
        if len(Global.ParseScanners) >= 2:
            query = ""
            for scanner in Global.ParseScanners:
                if query == "":
                    if subnet:
                        query += " select protocol from %sPorts where (protocol <> 'N/A' and IP like '%s')"%(scanner, (subnet+"%"))
                    else:
                        query += " select protocol from %sPorts where protocol <> 'N/A' "%scanner
                else:
                    if subnet:
                        query += " union select protocol from %sPorts where (protocol <> 'N/A' and IP like '%s')"%(scanner, (subnet+"%"))
                    else:
                        query += " union select protocol from %sPorts where protocol <> 'N/A' "%scanner
                        
            query += " order by protocol "
            
       
        rows = db.FetchAllRows(query)
        i = 0
        Protocols = []
        fout.write("<TR>\n")
        for row in rows:
            if row[0].lower() not in Protocols:
                Protocols.append(row[0].lower())
                fout.write("<td> %s </td>"%row[0])
                i += 1
                if i%15 == 0:
                    fout.write("</tr>")
                    
        fout.write("</table></font></p>\n")
       
        
        #fout.write("""<P align="left"><STRONG><FONT face="Arial" size="4">Unique Services:</FONT></STRONG><br/>""")
        #fout.write("""<FONT face="Arial" size="2">""")
        fout.write("""<TABLE id="Table5" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue">""")
        fout.write("""<FONT face="Arial" size="3">""")
        fout.write('<TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">')
        fout.write('<TH colspan=5>Unique Services</TH></TR></font>\n')
        if len(Global.ParseScanners) >= 2:
            query = ""
            for scanner in Global.ParseScanners:
                if query == "":
                    if subnet:
                        query += " select service from %sPorts where (service <> 'N/A' and IP like '%s')"%(scanner, (subnet+"%"))
                    else:
                        query += " select service from %sPorts where service <> 'N/A' "%scanner
                else:
                    if subnet:
                        query += " union select service from %sPorts where (service <> 'N/A' and IP like '%s')"%(scanner, (subnet+"%"))
                    else:
                        query += " union select service from %sPorts where service <> 'N/A' "%scanner
                        
            query += " order by service "
            
        rows = db.FetchAllRows(query)
        i = 0
        Services = []
        fout.write("<TR>\n")
        for row in rows:
            if row[0].strip():
                if row[0].lower() not in Services:
                    Services.append(row[0].lower())
                    fout.write("<TD> %s </TD>"%row[0])
                    i += 1
                    if i%5 == 0:
                        fout.write("</TR>\n")
                    
        fout.write("</Table></p>\n")
        
        fout.write("""</font></body></html>""")
        
    fout.close()    

    
def ConsolidatedUniqueOSReport(html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    global navigationQuery
    if html:
        fileName = 'ConsolidatedUniqueOSReport.html'
        if subnet:
            title = "List of Unique Operating Systems in Subnet %s"%subnet
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "Unique OS", "./%s/%s"%(subnet, fileName)),]) 
        else:
            title = "Network-wide List of Unique Operating Systems"
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', subnet, "Consolidated Reports", "Unique OS", "./%s"%(fileName)),]) 
            
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
        """%(title, title)
        fout.write(htmlHeader)
        #fout.write("""<P align="left"><STRONG><FONT face="Arial" size="4">Unique Ports:</FONT></STRONG><br/>""")
       
        fout.write("""<TABLE id="Table6" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">""")
        fout.write("""<FONT face="Arial" size="2">""")
        if len(Global.ParseScanners) > 2:
            query = ""
            for scanner in Global.ParseScanners:
                #if scanner.lower() != 'languard':
                if query == "":
                    if subnet:
                        query += " select OS from %sHosts where (OS <> 'N/A' and IP like '%s') "%(scanner, (subnet + "%"))
                    else:
                        query += " select OS from %sHosts where OS <> 'N/A' "%scanner
                else:
                    if subnet:
                        query += " union select OS from %sHosts where (OS <> 'N/A' and IP like '%s')"%(scanner, (subnet + "%"))
                    else:
                        query += " union select OS from %sHosts where OS <> 'N/A' "%scanner
                    
            query += " order by OS "
        
        col = 0
        
        fout.write("""<FONT face="Arial" size="3">""")
        fout.write('<TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">')
        fout.write('<TH colspan=20>Unique Operating Systems</TH></TR></font>\n')
        fout.write("<TR>\n")
        rows = db.FetchAllRows(query)
        OS = {}
        alphaRE = re.compile(r'([a-z]+)', re.I)
        for row in rows:
            newrow = row[0].replace(' or ', ';')
            newrow = newrow.replace(',', ';')
            newrow = newrow.replace('<br>', ';')
            newrow = newrow.replace('<br/>', ';')
            oslist = newrow.split(';')
            for os1 in oslist:
                if alphaRE.match(os1):
                    if not OS.has_key(os1.lower().strip()):
                        OS[os1.lower().strip()] = os1
                                
                
        for key in OS:
            if not os1:
                continue                       
            fout.write("<td> %s </td>"%OS[key])
            col += 1
            if col%5 == 0:
                fout.write("</tr>")
                
        fout.write("</table></font></p>\n")
        
        fout.write("""</font></body></html>""")
        
    fout.close()    


def ConsolidatedKeywordReport(Keyword, html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    Summary = []
    
    scannersCount = len(Global.ConsolidationScanners)
    
    i = 0
    keywordRE = re.compile(Keyword, re.I)
    global navigationQuery
    
    for scanner in Global.ConsolidationScanners:
        PortsTable = scanner + "Ports"
        if subnet:
            query = "select IP, Port, Service, Description from %s where (Service like '%s' or Description like '%s') and IP like '%s' order by IP;"%(PortsTable, ("%"+Keyword+"%"), ("%"+Keyword+"%"), (subnet+"%"))
        else:
            query = "select IP, Port, Service, Description from %s where (Service like '%s' or Description like '%s') order by IP;"%(PortsTable, ("%"+Keyword+"%"), ("%"+Keyword+"%"))
        #print query
        dbrows = db.FetchAllRows(query)
        #for each ip, port, service check if it already exists
        
        for dbrow in dbrows:
            exists = False
            ipPos = 0
            ipFound = False
            for row in Summary:
                #check if ip port and service all match
                #print 'row= ', row
                ipPos += 1
                if dbrow[0].lower().strip() == row[0].lower().strip():
                    ipFound = True
                    if dbrow[1] == row[1] and dbrow[2].lower().strip() == row[2].lower().strip():
                        exists = True
    
                        desc = dbrow[3].replace('<br/><br/><br/>', '<br/>')
                        desc = desc.replace('<br/><br/>', '<br/>')
                        highlight = '<FONT style="BACKGROUND-COLOR: #FFFF00">%s</FONT>'%Keyword
                        desc = re.sub(keywordRE, highlight, desc)
                        
                        #if len(desc) > 100:
                        #    row[3][i] = "%s ..."%desc[:100]
                        #else:
                        row[3][i] = "%s"%desc
                    break
                    
            if not exists:
                descriptions = []
                for sc in Global.ConsolidationScanners:
                    descriptions.append('X')

                desc = dbrow[3].replace('<br/><br/><br/>', '<br/>')
                desc = desc.replace('<br/><br/>', '<br/>')
                highlight = '<FONT style="BACKGROUND-COLOR: #FFFF00">%s</FONT>'%Keyword
                desc = re.sub(keywordRE, highlight, desc)
                """
                if len(desc) > 100:
                    descriptions[i] = "%s ..."%desc[:100]
                else:
                    descriptions[i] = "%s"%desc
                """
                descriptions[i] = "%s"%desc
                #print descriptions
                
                newRow = [dbrow[0], dbrow[1], dbrow[2], descriptions]

                if ipFound:
                    Summary.insert(ipPos, newRow)
                else:
                    Summary.append(newRow)
        i += 1       
    
            
    if html:
        fileName = 'Consolidated-%s-SummaryReport.html'%(Keyword)
        if subnet:
            title = '"%s" Summary Report in Subnet %s'%(Keyword, subnet)
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "%s - Summary"%Keyword, "./%s/%s"%(subnet, fileName)),]) 
        else:
            title = " Network-wide %s Summary Report"%(Keyword)
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', subnet, "Consolidated Reports", "%s - Summary"%Keyword, "./%s"%(fileName)),]) 
            
            
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <FONT face="Arial" size="4">
            <p>
        """%(title, title)
        
        htmlHeader += """
                <TABLE id="Table1" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TD>
                        IP
                    </TD>
                    <TD>
                        Port
                    </TD>
                    <TD>
                        Service
                    </TD>
                    """
        for scanner in Global.ConsolidationScanners:
            htmlHeader += "<TD>%s</TD>"%scanner
        htmlHeader += "</TR>"
     
        fout.write("%s\n"%htmlHeader)
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        
    for row in Summary:
        if html:
            fout.write('<TR>\n')
            fout.write('    <TD><b> %s </b></TD>\n'%(row[0]))
            if int(row[1]) == 100000:
                fout.write('    <TD> N/A </TD>\n')
            else:
                fout.write('    <TD> %s </TD>\n'%(row[1]))
            highlight = '<FONT style="BACKGROUND-COLOR: #FFFF00">%s</FONT>'%Keyword
            service = re.sub(keywordRE, highlight, row[2])
            fout.write('    <TD> %s </TD>\n'%(service))
            for des in row[3]:
                fout.write('    <TD> %s </TD>\n'%(des))
            fout.write('</TR>\n')
    if html:
        fout.write(htmlFooter)
        
    fout.close()    


def ConsolidatedUniqueHostsReport(html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    Summary = []
    #first get all IPs
    query = ""
    for scanner in Global.ParseScanners:
        if query == "":
            if subnet:
                query += " select distinct IP from %sHosts where IP like '%s'"%(scanner, (subnet+"%"))
            else:
                query += " select distinct IP from %sHosts "%scanner
        else:
            if subnet:
                query += " union select distinct IP from %sHosts where IP like '%s'"%(scanner, (subnet+"%"))
            else:
                query += " union select distinct IP from %sHosts "%scanner
                    
    query += " order by IP "
    
    uniqueIPs = db.FetchAllRows(query)
    for ip in uniqueIPs:
        row = [ip[0], '']
        for scanner in Global.ParseScanners:
            HostsTable = scanner + "Hosts"
            PortsTable = scanner + "Ports"
            query = "select HostName, OS from %s where IP = '%s';"%(HostsTable, ip[0])
            query1 = "select count(Port) from  %s where IP = '%s' and Port <> 100000;"%(PortsTable, ip[0])
            #print query
            dbrows = db.FetchAllRows(query)
            portCounts = db.FetchAllRows(query1)
            if len(dbrows) == 0:
                if row[1] == '':
                    row[1] += "X # X # X"
                else:
                    row[1] += " | X # X # X"
                
            else:
                for dbrow in dbrows:
                    if row[1] == '':
                        row[1] += dbrow[0] + " # " + dbrow[1] + " # " + str(portCounts[0][0])
                    else:
                        row[1] += " | " + dbrow[0] + " # " + dbrow[1] + " # " + str(portCounts[0][0])
                        
        Summary.append(row)
       
    global navigationQuery                    
    if html:
        fileName = 'ConsolidatedUniqueHostsReport.html'
        if subnet:
            title = "Unique Hosts Report in Subnet %s"%subnet
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "Unique Hosts", "./%s/%s"%(subnet, fileName)),]) 
        else:
            title = "Network-wide Unique Hosts Report"
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "Unique Hosts", "./%s"%(fileName)),]) 
            
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <FONT face="Arial" size="3">
            <p>
            Total Hosts Detected: %d
            </p>
            <p>
        """%(title, title, len(uniqueIPs))
        
        htmlHeader += """
                <TABLE id="Table7" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TH rowspan=2>
                        IP
                    </TH>
                    
                    """

        for scanner in Global.ParseScanners:
            htmlHeader += "<TH colspan=3>%s</TH>"%scanner
        
        htmlHeader += "</TR>"
             
        fout.write("%s\n"%htmlHeader)

    fout.write('<tr  style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">')
    for scanner in Global.ParseScanners:
        fout.write('<td>HostName</td>')
        fout.write('<td>OS</td>')
        fout.write('<td>Ports</td>')
    fout.write('</tr>\n')
    for row in Summary:
        if html:
            fout.write('<TR>\n')
            fout.write('    <TD><b> %s </b></TD>\n'%(row[0]))
            scanlist = row[1].split(' | ')
            for scan in scanlist:
                oslist = scan.split(' # ')
                for des in oslist:
                    if not des:
                        continue
                    fout.write('    <TD> %s </TD>\n'%(des))
                #fout.write('    <TD> %s </TD>\n'%(row[1]))
            fout.write('</TR>\n')
            
    if html:
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        fout.write(htmlFooter)
        
    fout.close()

def Top5CommonVulnerabilitiesWithHosts(Scanner, severity, subnet=""):
    """"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    portsTable = Scanner + "Ports"
    risk = "High"
    if severity == 2:
        risk = "Medium"
    if severity == 1:
        risk = "Low"
    
    global navigationQuery
    fileName = "%sTop5%sCommonVulnerabilitiesWithHosts.txt"%(Scanner, risk)    
    if subnet:
        dirPath = os.path.join(Config["OutputPath"], subnet)
        fout = open(os.path.join(dirPath, fileName), 'w')
        fout.write("%s - Vulnerabilities by Risk Level in Subnet %s\n\n"%(Scanner, subnet))
        queryTop = "select count(Description) as Frequency, Description from %s where (severity = %s and Subnet='%s') group by Description order by Frequency desc limit 5;"%(portsTable, str(severity), subnet)
        db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Reports"%Scanner, "Top 5 Common %s Vulnerabilities"%risk, "./%s/%s"%(subnet, fileName)),]) 
    else:
        fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
        queryTop = "select count(Description) as Frequency,  Description from %s where severity = %s group by Description order by Frequency desc limit 5;"%(portsTable, str(severity))
        fout.write("%s - Vulnerabilities by Risk Level\n\n"%Scanner)
        db.ExecuteMany(navigationQuery, [('Network', '', "%s Reports"%Scanner, "Top 5 Common %s Vulnerabilities"%risk, "./%s"%(fileName)),]) 
        

    rowsTop = db.FetchAllRows(queryTop)
    
     
    fout.write("Top 5 %s Vulnerabilities with corresponding hosts:\n\n"%risk)
    
    i = 1
    for rowTop in rowsTop:
        vuln = str(rowTop[1])
        fout.write("%s. %s\n"%(i, vuln))
        fout.write('Vulnerability Frequency: %s\n'%str(rowTop[0]))
        if subnet:
            query = "select distinct(IP) from %s where (Description = %s and Subnet='%s') order by IP;"%(portsTable, db.SqlSQuote(vuln), subnet)
        else:
            query = "select distinct(IP) from %s where Description = %s order by IP;"%(portsTable, db.SqlSQuote(vuln))
        rows = db.FetchAllRows(query)
        fout.write("Hosts Frequency: %s\n\n"%(str(len(rows))))
        fout.write('Hosts:\n')
        col = 0
        for row in rows:
            if col == 4:
                col = 0
                fout.write("\n")
            fout.write("%s"%(str(row[0]).ljust(30)))
            col += 1
        fout.write("\n\n")
        i += 1
    fout.close()
    db.CloseConnection()
    
    
def IndividualDShieldTopTenPorts(scannerName, html=True, subnet=""):
    #This Report is obsolete as everything is reported by Consolidated version
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    portsTable = scannerName + "Ports"
    if subnet:
        query = "select IP, Port, Service, Description, CVEID from %s where (IP like '%s' and Port in %s) order by IP, Port;"%(portsTable, (subnet+"%"), str(tuple(Config["TopTenByReports"])))
        query1 = "select IP, Port, Service, Description, CVEID from %s where (IP like '%s' and Port in %s) order by IP, Port;"%(portsTable, (subnet+"%s"), str(tuple(Config["TopTenByTargets"])))
    else:
        query = "select IP, Port, Service, Description, CVEID from %s where Port in %s order by IP, Port;"%(portsTable, str(tuple(Config["TopTenByReports"])))
        query1 = "select IP, Port, Service, Description, CVEID from %s where Port in %s order by IP, Port;"%(portsTable, str(tuple(Config["TopTenByTargets"])))
    rows = db.FetchAllRows(query)
    
    rows1 = db.FetchAllRows(query1)
        
    global navigationQuery
    if html:
        fileName = '%sDShieldTopTenPortsByReports.html'%(scannerName)
        fileName1 = '%sDShieldTopTenPortsByTargets.html'%(scannerName)
        if subnet:
            title = "%s - List of Hosts with Top Ten Ports in Subnet %s (By Reports)"%(scannerName, subnet)
            title1 = "%s - List of Hosts with Top Ten Ports in Subnet %s (By Targets)"%(scannerName, subnet)
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            fout1 = open(os.path.join(dirPath, fileName1), 'w')
            topTenPorts = "Top Ten Ports %s By Reports"%(str(Config["TopTenByReports"]))
            topTenPorts1 = "Top Ten Ports %s By Targets"%(str(Config["TopTenByTargets"]))
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Reports"%scannerName, "D-Shield Top Ten Ports By Reports", "./%s/%s"%(subnet, fileName)),]) 
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Reports"%scannerName, "D-Shield Top Ten Ports By Targets", "./%s/%s"%(subnet, fileName1)),]) 
        else:
            title = "%s - Network-wide List of Hosts with Top Ten Ports (By Reports)"%scannerName
            title1 = "%s - Network-wide List of Hosts with Top Ten Ports (By Targets)"%scannerName
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            fout1 = open(os.path.join(Config["OutputPath"], fileName1), 'w')

            topTenPorts = "Top Ten Ports By Reports %s"%str(Config["TopTenByReports"])
            topTenPorts1 = "Top Ten Ports By Targets %s"%str(Config["TopTenByTargets"])
            
            db.ExecuteMany(navigationQuery, [('Network', '', "%s Reports"%scannerName, "D-Shield Top Ten Ports By Reports", "./%s"%(fileName)),]) 
            db.ExecuteMany(navigationQuery, [('Network', '', "%s Reports"%scannerName, "D-Shield Top Ten Ports By Targets", "./%s"%(fileName1)),]) 
            
        
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
        </head>
        <body>
        <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
        <P align="center"> <strong><FONT face="Arial" size="3"><a href="http://www.dshield.org/top10.html" target="_blank">
        (http://www.dshield.org/top10.html)</a></font></strong></p>
        <P align="center"><STRONG><FONT face="Arial" size="2">%s</FONT></STRONG></P>
        <p><FONT face="Arial" size="3">
        """%(title, title, topTenPorts)
        
        htmlHeader1 = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
        </head>
        <body>
        <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
        <P align="center"> <strong><FONT face="Arial" size="3"><a href="http://www.dshield.org/top10.html" target="_blank">
        (http://www.dshield.org/top10.html)</a></font></strong></p>
        <P align="center"><STRONG><FONT face="Arial" size="2">%s</FONT></STRONG></P>
        <p><FONT face="Arial" size="3">
        """%(title1, title1, topTenPorts1)
        
        tableHeader = """
                <TABLE id="Table1" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TD>IP
                    </TD>
                    <TD>
                        Port
                    </TD>
                    <TD>
                        Service
                    </TD>
                    <TD>
                        Description
                    </TD>
                    <TD>
                        CVE
                    </TD>
                </TR>
        """
        htmlHeader += tableHeader
        
        htmlHeader1 += tableHeader
        
        fout.write("%s\n"%htmlHeader)
        fout1.write("%s\n"%htmlHeader1)
        htmlFooter = """
                </TABLE>
            </font>
            </p>
           
        </body>
        </html>
        """
    for row in rows:
        if html:
            fout.write('<TR>\n')
            fout.write('    <TD><b> %s </b></TD>\n'%(row[0]))
            port = row[1]
            if port == 100000:
                port = 'N/A'
            
            fout.write('    <TD> %s </TD>\n'%(port))
            fout.write('    <TD> %s </TD>\n'%(row[2]))
            fout.write('    <TD> %s </TD>\n'%(row[3].replace("=> ", "")))
            fout.write('    <TD> %s </TD>\n'%(row[4]))
            fout.write('</TR>\n')
            
    for row in rows1:
        if html:
            fout1.write('<TR>\n')
            fout1.write('    <TD><b> %s </b></TD>\n'%(row[0]))
            port = row[1]
            if port == 100000:
                port = 'N/A'
            
            fout1.write('    <TD> %s </TD>\n'%(port))
            fout1.write('    <TD> %s </TD>\n'%(row[2]))
            fout1.write('    <TD> %s </TD>\n'%(row[3].replace("=> ", "")))
            fout1.write('    <TD> %s </TD>\n'%(row[4]))
            fout1.write('</TR>\n')
    if html:
        fout.write(htmlFooter)
        fout1.write(htmlFooter)
        
    fout.close()
    fout1.close()
    
    
def ConsolidatedDShieldTopTenPorts(topTenType, html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    Summary = []
    global navigationQuery
    portsTable = Global.ConsolidationPortScanners[0] + "Ports"
    
    yesImage = '<img src="assets/yes.gif" alt="Yes">'
    noImage = '<img src="assets/no.gif" alt="No">'
    if subnet:
        yesImage = '<img src="../assets/yes.gif" alt="Yes">'
        noImage = '<img src="../assets/no.gif" alt="No">'
            
    
    if html:
        if topTenType == 0:
            fileName = 'ConsolidatedDShieldTopTenPortsByReports.html'
            if subnet:
                title = "List of Hosts with Top Ten Ports (By Reports) in Subnet %s"%subnet
                topTenPorts = "Top Ten Ports %s By Reports"%str(Config["TopTenByReports"])
                query = "select distinct IP, Port, Service from %s where (Port in %s and IP like '%s') order by IP, Port;"%(portsTable, str(tuple(Config["TopTenByReports"])), (subnet+"%"))
                dirPath = os.path.join(Config["OutputPath"], subnet)
                fout = open(os.path.join(dirPath, fileName), 'w')
                db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "D-Shield Top Ten Ports By Reports", "./%s/%s"%(subnet, fileName)),]) 
            
            else:
                title = "Network-wide List of Hosts with Top Ten Ports (By Reports)"
                topTenPorts = "Top Ten Ports %s By Reports"%str(Config["TopTenByReports"])
                fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
                query = "select distinct IP, Port, Service from %s where Port in %s order by IP, Port;"%(portsTable, str(tuple(Config["TopTenByReports"])))
                db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "D-Shield Top Ten Ports By Reports", "./%s"%(fileName)),]) 
        
        else:
            fileName = 'ConsolidatedDShieldTopTenPortsByTargets.html'
            if subnet:
                title = "List of Hosts with Top Ten Ports (By Targets) in Subnet %s"%subnet
                query = "select distinct IP, Port, Service from %s where (Port in %s and IP like '%s') order by IP, Port;"%(portsTable, str(tuple(Config["TopTenByTargets"])), (subnet+"%"))
                topTenPorts = "Top Ten Ports %s By Targets "%str(Config["TopTenByTargets"])
                dirPath = os.path.join(Config["OutputPath"], subnet)
                fout = open(os.path.join(dirPath, fileName), 'w')
                db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "D-Shield Top Ten Ports By Targets", "./%s/%s"%(subnet, fileName)),]) 
            else:
                title = "Network-wide List of Hosts with Top Ten Ports (By Targets)"
                query = "select distinct IP, Port, Service from %s where Port in %s order by IP, Port;"%(portsTable, str(Config["TopTenByTargets"]))
                topTenPorts = "Top Ten Ports %s By Targets "%str(Config["TopTenByTargets"])
                fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
                db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "D-Shield Top Ten Ports By Targets", "./%s"%(fileName)),]) 
                
        rows = db.FetchAllRows(query)

        for row in rows:
            #key += 1
            Summary.append([row[0], row[1], row[2].lower(), "1"])
            
        scannerPos = 0
        for scanner in Global.ConsolidationPortScanners[1:]:
            scannerPos += 1
            portsTable = scanner + "Ports"
            if topTenType == 0:
                if subnet:
                    query = "select distinct IP, Port, Service from %s where (Port in %s and IP like '%s') order by IP, Port;"%(portsTable, str(Config["TopTenByReports"]), (subnet+"%"))
                else:
                    query = "select distinct IP, Port, Service from %s where Port in %s order by IP, Port;"%(portsTable, str(Config["TopTenByReports"]))
            
            else:
                if subnet:
                    query = "select distinct IP, Port, Service from %s where (Port in %s and IP like '%s') order by IP, Port;"%(portsTable, str(Config["TopTenByTargets"]), (subnet+"%"))
                else:
                    query = "select distinct IP, Port, Service from %s where Port in %s order by IP, Port;"%(portsTable, str(Config["TopTenByTargets"]))
            
            rows = db.FetchAllRows(query)
            for row in rows:
                found = False
                i = 0
                for srow in Summary:
                    if srow[0] == row[0] and srow[1] == row[1] and srow[2] == row[2].lower():
                        found = True
                        Summary[i][3] += "1"
                        break
                    i += 1
                if not found:
                    #key += 1
                    val = ""
                    pos = 0
                    while pos < scannerPos:
                        val += "0"
                        pos += 1
                        
                    val += "1"
                    Summary.append([row[0], row[1], row[2].lower(), val])
             
                           
    if html:
        
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <P align="center"> <strong><FONT face="Arial" size="3"><a href="http://www.dshield.org/top10.html" target="_blank">
            (http://www.dshield.org/top10.html)</a></font></strong></p>
            <P align="center"><STRONG><FONT face="Arial" size="2">%s</FONT></STRONG></P>
            <P align="left"><STRONG><FONT face="Arial" size="3">Note: %s &nbsp; Reported &nbsp;&nbsp;&nbsp; %s &nbsp; Not Reported
            </P>
            <FONT face="Arial" size="3">
            <p>
        """%(title, title, topTenPorts, yesImage, noImage)
        
        htmlHeader += """
                <TABLE id="Table7" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TH>
                        IP
                    </TH>
                    <TH>
                        Port
                    </TH>
                    <TH>
                        Service
                    </TH>
                    """

        for scanner in Global.ConsolidationPortScanners:
            htmlHeader += "<TH>%s</TH>"%scanner
        
        htmlHeader += "</TR>"
             
        fout.write("%s\n"%htmlHeader)

    for srow in Summary:
        if html:
            fout.write('<TR>\n')
            i = 0
            for col in srow:
                if i < 3:
                    if i == 0:
                        fout.write('    <TD><b> %s </b></TD>\n'%(col))
                    else:
                        fout.write('    <TD> %s </TD>\n'%(col))
                else:
                    value = col
                i += 1
                #else:
                #value = Summary[akey][ikey]
            for ch in value:
                if ch == "1":
                    fout.write('    <TD> %s </TD>\n'%yesImage)
                else:
                    fout.write('    <TD> %s </TD>\n'%noImage)
                
            scannerCount = len(value)
            while scannerCount < len(Global.ConsolidationPortScanners):
                fout.write('    <TD> %s </TD>\n'%noImage)
                scannerCount += 1
           
            fout.write('</TR>\n')
            
    if html:
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        fout.write(htmlFooter)
        
    fout.close()


def ConsolidatedHostsWithOpenPorts(html=True, subnet="", ipwise=False):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    Summary = []
    yesImage = '<img src="assets/yes.gif" alt="Yes">'
    noImage = '<img src="assets/no.gif" alt="No">'
    if subnet:
        yesImage = '<img src="../assets/yes.gif" alt="Yes">'
        noImage = '<img src="../assets/no.gif" alt="No">'
    elif ipwise:
        yesImage = '<img src="../../assets/yes.gif" alt="Yes">'
        noImage = '<img src="../../assets/no.gif" alt="No">'
        
    portsTable = Global.ConsolidationPortScanners[0] + "Ports"
    global navigationQuery
    if html:
        fileName = 'ConsolidatedHostsWithOpenPorts.html'
        if subnet:
            title = "List of Hosts with all Open Ports in Subnet %s"%subnet
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Consolidated Reports", "Hosts With Open Ports", "./%s/%s"%(subnet, fileName)),]) 
        else:
            if not ipwise:
                title = "Consolidated - Network-wide List of Hosts with all Open Ports"
                fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
                db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "Hosts With Open Ports", "./%s"%(fileName)),]) 

        query = ""
        
        for scanner in Global.ConsolidationPortScanners:
            if query == "":
                if subnet:
                    query += " select distinct IP from %sHosts where IP like '%s' "%(scanner, (subnet+"%"))
                else:
                    query += " select distinct IP from %sHosts "%scanner
            else:
                if subnet:
                    query += " union select distinct IP from %sHosts where IP like '%s' "%(scanner, (subnet+"%"))
                else:
                    query += " union select distinct IP from %sHosts "%scanner
                    
        query += " order by IP "
    
        uniqueIPs = db.FetchAllRows(query)
        for ip in uniqueIPs:
            #if ipwise:
            #    Summary = []
                
            IPRows = []
            if subnet:
                query = "select distinct IP, Port, Service from %s where Port <> 100000 and IP='%s' order by Port;"%(portsTable, ip[0])
            else:
                fileName = 'UniquePortProtocolService.html'
                query = "select distinct IP, Port, Service from %s where Port <> 100000 and IP='%s' order by Port;"%(portsTable, ip[0])
                """
                if ipwise:
                    db.ExecuteMany(navigationQuery, [('Individual', ip[0], "Consolidated Reports", "Unique Ports Protocols Services", "./IndividualIP/%s/%s"%(ip[0], fileName)),]) 
                    title = "Consolidated Unique Open Ports and Services for IP: %s"%(ip[0])
                    dirPath = os.path.join(Config["OutputPath, 'IndividualIP')
                    
                    dirPath = os.path.join(dirPath, ip[0])
                    if not os.path.exists(dirPath):
                        os.makedirs(dirPath)
                        
                    destImage = os.path.join(dirPath, 'Images')
                    if not os.path.exists(destImage):
                        shutil.copytree('Images', destImage)
                        
                    fout = open(os.path.join(dirPath, fileName), 'w')
                """
               
            rows = db.FetchAllRows(query)
            for arow in rows:
                IPRows.append([arow[0], arow[1], arow[2].lower().strip(), "1"])
                
            scannerPos = 0
            for scanner in Global.ConsolidationPortScanners[1:]:
                scannerPos += 1
                portsTable = scanner + "Ports"
                query = "select distinct IP, Port, Service from %s where Port <> 100000 and IP='%s' order by Port;"%(portsTable, ip[0])
                
                rows = db.FetchAllRows(query)
                for row in rows:
                    found = False
                    i = 0
                    for srow in IPRows:
                        if srow[0] == row[0] and srow[1] == row[1] and srow[2] == row[2].lower().strip():
                            found = True
                            IPRows[i][3] += "1"
                            break
                        i += 1
                    if not found:
                        val = ""
                        pos = 0
                        while pos < scannerPos:
                            val += "0"
                            pos += 1
                            
                        val += "1"
                        IPRows.append([row[0], row[1], row[2].lower().strip(), val])
                  
            if not ipwise:      
                for row in IPRows:
                    Summary.append(row)
                
            if ipwise:
                if len(IPRows) <1:
                    continue
                
                if html:
                    
                    db.ExecuteMany(navigationQuery, [('Individual', ip[0], "Consolidated Reports", "Unique Ports Protocols Services", "./IndividualIP/%s/%s"%(ip[0], fileName)),]) 
                    title = "Consolidated Unique Open Ports and Services for IP: %s"%(ip[0])
                    dirPath = os.path.join(Config["OutputPath"], 'IndividualIP')
                    
                    dirPath = os.path.join(dirPath, ip[0])
                    if not os.path.exists(dirPath):
                        os.makedirs(dirPath)
                        
                    """
                    destImage = os.path.join(dirPath, 'Images')
                    if not os.path.exists(destImage):
                        shutil.copytree('Images', destImage)
                    """
                     
                    fout = open(os.path.join(dirPath, fileName), 'w')
                    
                    htmlHeader = """
                    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
                    <html>
                    <head>
                    <title>%s</title>
                    
                    </head>
                    <body>
                        <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
                        <P align="left"><STRONG><FONT face="Arial" size="3">Note: %s &nbsp; Reported &nbsp;&nbsp;&nbsp; %s &nbsp; Not Reported
                        </P>
                        <FONT face="Arial" size="3">
                        <p>
                    """%(title, title, yesImage, noImage)
                    
                    htmlHeader += """
                            <TABLE id="Table7" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                            <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                                <TH>
                                    IP
                                </TH>
                                <TH>
                                    Port
                                </TH>
                                <TH>
                                    Service
                                </TH>
                                """

                    for scanner in Global.ConsolidationPortScanners:
                        htmlHeader += "<TH>%s</TH>"%scanner
                    
                    htmlHeader += "</TR>"

                    fout.write("%s\n"%htmlHeader)
                    
                for srow in IPRows:
                    if html:
                        fout.write('<TR>\n')
                        i = 0
                        for col in srow:
                            if i < 3:
                                if i == 0:
                                    fout.write('    <TD><b> %s </b></TD>\n'%(col))
                                else:
                                    fout.write('    <TD> %s </TD>\n'%(col))
                            else:
                                value = col
                            i += 1

                        for ch in value:
                            if ch == "1":
                                fout.write('    <TD> %s </TD>\n'%yesImage)
                            else:
                                fout.write('    <TD> %s </TD>\n'%noImage)
                            
                        scannerCount = len(value)
                        while scannerCount < len(Global.ConsolidationPortScanners):
                            fout.write('    <TD> %s </TD>\n'%noImage)
                            scannerCount += 1
                       
                        fout.write('</TR>\n')
                        
                if html:
                    htmlFooter = """
                            </TABLE>
                        </p>
                        </font>
                    </body>
                    </html>
                    """
                    fout.write(htmlFooter)
                    
                fout.close()
    
       
    if ipwise:
        return
                        
    if html:
        
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <P align="left"><STRONG><FONT face="Arial" size="3">Note: %s &nbsp; Reported &nbsp;&nbsp;&nbsp;
            %s &nbsp; Not Reported
            </P>
            <FONT face="Arial" size="3">
            <p>
        """%(title, title, yesImage, noImage)
        
        htmlHeader += """
                <TABLE id="Table7" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TH>
                        IP
                    </TH>
                    <TH>
                        Port
                    </TH>
                    <TH>
                        Service
                    </TH>
                    """

        for scanner in Global.ConsolidationPortScanners:
            htmlHeader += "<TH>%s</TH>"%scanner
        
        htmlHeader += "</TR>"

        fout.write("%s\n"%htmlHeader)
        
    for srow in Summary:
        if html:
            fout.write('<TR>\n')
            i = 0
            for col in srow:
                if i < 3:
                    if i == 0:
                        fout.write('    <TD><b> %s </b></TD>\n'%(col))
                    else:
                        fout.write('    <TD> %s </TD>\n'%(col))
                else:
                    value = col
                i += 1

            for ch in value:
                if ch == "1":
                    fout.write('    <TD> %s </TD>\n'%yesImage)
                else:
                    fout.write('    <TD> %s </TD>\n'%noImage)
                
            scannerCount = len(value)
            while scannerCount < len(Global.ConsolidationPortScanners):
                fout.write('    <TD> %s </TD>\n'%noImage)
                scannerCount += 1
           
            fout.write('</TR>\n')
            
    if html:
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        fout.write(htmlFooter)
        
    fout.close()
    
    
def GetHostsSubnets():
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    global SubnetHostsSet
    
    for scanner in Global.ConsolidationScanners: 
        hostsTable = scanner + "Hosts"
        query = "select distinct Subnet from %s ;"%(hostsTable)
        rows = db.FetchAllRows(query)
        for row in rows:
            if not row[0].strip():
                continue
            
            #if SubnetHostsSet.has_key(scanner):
            SubnetHostsSet.add(row[0].strip())
            #else:
            #    SubnetHostsSet[scanner] = set([subnet])
            
    db.CloseConnection()
    
def CompromisedIPsReport(html=True):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
        
    global navigationQuery
    
    if html:
        fileName = 'ListOfCompromisedIPs.html'
        title = 'List of Compromised IPs with Related Vulnerablity'
        fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
        db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "Compromised Systems", "./%s"%(fileName)),]) 
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
        </head>
        <body>
        <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
        <p><FONT face="Arial" size="3">
        """%(title, title)
        
        tableHeader = """
                <TABLE id="Table1" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TD>IP
                    </TD>
                    <TD>
                        Port
                    </TD>
                    <TD>
                        Service
                    </TD>
                    <TD>
                        Exploit Name
                    </TD>
                </TR>
        """
        htmlHeader += tableHeader
        
        fout.write("%s\n"%htmlHeader)
        htmlFooter = """
                </TABLE>
            </font>
            </p>
           
        </body>
        </html>
        """
        
    for ipTuple in Config["CompromisedIPs"]:
        if html:
            fout.write('<TR>\n')
            i = 0
            for tpvalue in ipTuple:
                if i == 0:
                    fout.write('    <TD><b> %s </b></TD>\n'%(tpvalue))
                else:
                    fout.write('    <TD> %s </TD>\n'%(tpvalue))
                i += 0
            #fout.write('    <TD> %s </TD>\n'%(ipTuple[2]))
            #fout.write('    <TD> %s </TD>\n'%(ipTuple[3]))
            fout.write('</TR>\n')

    if html:
        fout.write(htmlFooter)
        
        
    fout.close()
   
   


def IndScannerTop5HostsWithOpenPortsAndServices(html=True):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
        
    for Scanner in Global.ConsolidationScanners:
        hostsTable = Scanner + "Hosts"
        portsTable = Scanner + "Ports"
        query = "select IP, High, Medium, Low from %s order by High desc, Medium desc, Low desc limit 5;"%(hostsTable)
    
        rows = db.FetchAllRows(query)
        global navigationQuery
        if html:
            fileName = '%sTop5VulnHostsWithOpenPortsAndServices.html'%(Scanner)

            title = "%s - Top 5 Vulnerable Hosts with Open Ports and Services"%(Scanner)
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', '', "%s Reports"%Scanner, "Top 5 Vulnerable Hosts", "./%s"%(fileName)),]) 
            htmlHeader = """
            <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
            <html>
            <head>
            <title>%s</title>
            
            </head>
            <body>
                <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
                <FONT face="Arial" size="3">
            """%(title, title)
            fout.write(htmlHeader)
            i = 0
            for row in rows:
                i += 1
                htmlTable = '<b>%d.</b> IP: <b>%s</b>  High: <b>%d</b>  Medium: <b>%d</b>  Low: <b>%d</b><br />'%(i, row[0], row[1], row[2], row[3])
                query = "select distinct IP, Port, Service from %s where Port <> 100000 and IP='%s' order by Port;"%(portsTable, row[0])
                
                rowsPorts = db.FetchAllRows(query)
                htmlTable += """
                <TABLE id="Table7" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                    <TH>
                        IP
                    </TH>
                    <TH>
                        Port
                    </TH>
                    <TH>
                        Service
                    </TH>
                </TR>
                """
                htmlTable += '<TR>\n'
                for arow in rowsPorts:
                    for col in arow:
                        htmlTable += '<TD> %s </TD>\n'%(col)
                          
                    htmlTable += '</TR>\n'
                htmlTable += '</TABLE><br />\n'
                fout.write(htmlTable)       
            htmlFooter = """
                </font>
            </body>
            </html>
            """
            fout.write(htmlFooter)
                        
            fout.close()
    
def ConsolidatedTop5HostsWithOpenPortsAndServices(html=True):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    #Summary = []
       
       
    #for Scanner in Config["ConsolidationScanners:
    
    hostsTable = Global.ConsolidatedScannerName + "Hosts"
    
    query = "select IP, High, Medium, Low from %s order by High desc, Medium desc, Low desc limit 5;"%(hostsTable)

    rows = db.FetchAllRows(query)
    global navigationQuery
    yesImage = '<img src="assets/yes.gif" alt="Yes">'
    noImage = '<img src="assets/no.gif" alt="No">'
        
    if html:
        fileName = 'ConsolidatedTop5VulnHostsWithOpenPortsAndServices.html'

        title = "Consolidated - Top 5 Vulnerable Hosts with Open Ports and Services"
        fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
        db.ExecuteMany(navigationQuery, [('Network', '', "Consolidated Reports", "Top 5 Vulnerable Hosts", "./%s"%(fileName)),]) 
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
        <title>%s</title>
        
        </head>
               
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <P align="left"><STRONG><FONT face="Arial" size="3">Note: %s &nbsp; Reported &nbsp;&nbsp;&nbsp;
            %s &nbsp; Not Reported
            </STRONG></P>
            <FONT face="Arial" size="3">
        """%(title, title, yesImage, noImage)
        fout.write(htmlHeader)
        
        Rank = 0
    
        for row in rows:
            Rank += 1
            htmlTable = '<b>%d.</b> IP: <b>%s</b>  High: <b>%d</b>  Medium: <b>%d</b>  Low: <b>%d</b><br />'%(Rank, row[0], row[1], row[2], row[3])
            
            IPRows = []
            portsTable = Global.ConsolidationPortScanners[0] + "Ports"
            query = "select distinct IP, Port, Service from %s where Port <> 100000 and IP='%s' order by Port;"%(portsTable, row[0])
               
            rowsPorts = db.FetchAllRows(query)
            for arow in rowsPorts:
                IPRows.append([arow[0], arow[1], arow[2].lower(), "1"])
                
            scannerPos = 0
            for scanner in Global.ConsolidationPortScanners[1:]:
                scannerPos += 1
                portsTable = scanner + "Ports"
                query = "select distinct IP, Port, Service from %s where Port <> 100000 and IP='%s' order by Port;"%(portsTable, row[0])
                
                rowPorts = db.FetchAllRows(query)
                for arow in rowPorts:
                    found = False
                    i = 0
                    for srow in IPRows:
                        if srow[0] == arow[0] and srow[1] == arow[1] and srow[2] == arow[2].lower():
                            found = True
                            IPRows[i][3] += "1"
                            break
                        i += 1
                    if not found:
                        val = ""
                        pos = 0
                        while pos < scannerPos:
                            val += "0"
                            pos += 1
                            
                        val += "1"
                        IPRows.append([arow[0], arow[1], arow[2].lower(), val])
                        
            #for ipRow in IPRows:
            #Summary.append(ipRow)
                        
            tableBody = htmlTable + """
                    <TABLE id="Table7" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                    <TR style="BACKGROUND-COLOR: LightSteelBlue; color:black; font-weight:bold" align="center">
                        <TH>
                            IP
                        </TH>
                        <TH>
                            Port
                        </TH>
                        <TH>
                            Service
                        </TH>
                        """

            for scanner in Global.ConsolidationPortScanners:
                tableBody += "<TH>%s</TH>"%scanner
                
            tableBody += "</TR>"
        
            for srow in IPRows:
                if html:
                    tableBody += '<TR>\n'
                    value = srow[3]
                    for col in srow[:-1]:
                        tableBody += '    <TD> %s </TD>\n'%(col)

                    for ch in value:
                        if ch == "1":
                            tableBody += '    <TD> %s </TD>\n'%yesImage
                        else:
                            tableBody += '    <TD> %s </TD>\n'%noImage
                        
                    scannerCount = len(value)
                    while scannerCount < len(Global.ConsolidationPortScanners):
                        tableBody +='    <TD> %s </TD>\n'%noImage
                        scannerCount += 1
                   
                    tableBody +='</TR>\n'
            tableBody += "</TABLE><BR />"
            fout.write(tableBody)

        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        fout.write(htmlFooter)
        
        fout.close()
        

def ListIPsWithSpecialKeywords(Keyword, html=True, subnet=""):
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
       
    IPs = set()
    
    scannersCount = len(Global.ConsolidationScanners)
    global navigationQuery
    for scanner in Global.ConsolidationScanners:
        PortsTable = scanner + "Ports"
        if subnet:
            query = "select distinct IP from %s where (Service like '%s' or Description like '%s') and IP like '%s' order by IP;"%(PortsTable, ("%"+Keyword+"%"), ("%"+Keyword+"%"), (subnet+"%"))
        else:
            query = "select distinct IP from %s where (Service like '%s' or Description like '%s') order by IP;"%(PortsTable, ("%"+Keyword+"%"), ("%"+Keyword+"%"))
        #print query
        dbrows = db.FetchAllRows(query)
        #for each ip, port, service check if it already exists
        
        for row in dbrows:
            IPs.add(row[0])
    
    if html:
        fileName = 'IPListFor- %s.html'%(Keyword)
        if subnet:
            title = 'List of IPs for "%s" in Subnet %s'%(Keyword, subnet)
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fout = open(os.path.join(dirPath, fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "Misc. Reports", "%s"%Keyword, "./%s/%s"%(subnet, fileName)),])
        else:
            title = ' Network-wide List of IPs for "%s" '%(Keyword)
            fout = open(os.path.join(Config["OutputPath"], fileName), 'w')
            db.ExecuteMany(navigationQuery, [('Network', '', "Misc. Reports", "%s"%Keyword, "./%s"%(fileName)),]) 
            
        htmlHeader = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
        <html>
        <head>
		<title>%s</title>
		
        </head>
        <body>
            <P align="center"><STRONG><FONT face="Arial" size="5">%s</FONT></STRONG></P>
            <FONT face="Arial" size="4">
            <p>
        """%(title, title)
        
        totalColumns = 5
        htmlHeader += """
                <TABLE id="Table1" cellSpacing="0" cellPadding="2" width="100%" border="1"  borderColor="LightSteelBlue" style="font-size:small">
                    """
     
        fout.write("%s\n"%htmlHeader)

    i = 0
    IPList = list(IPs)
        
    IPList.sort()
    fout.write('<TR>\n')
    for ip in IPList:
        if html:
            if i%(totalColumns) == 0: 
                fout.write('</TR>\n')
                fout.write('<TR>\n')
            fout.write('    <TD> %s </TD>\n'%(ip))
            i += 1
            
    fout.write('</TR>\n')
    if html:
        htmlFooter = """
                </TABLE>
            </p>
            </font>
        </body>
        </html>
        """
        fout.write(htmlFooter)
        
    fout.close()    
    
def main():
    #ReadConfigFile()
    
    print 'Generating network-wide reports!'
    GetHostsSubnets()
    
    if not os.path.isdir(Config["OutputPath"]):
        os.mkdir(Config["OutputPath"])
    
    assetsFolder = 'assets'
    destFolder = os.path.join(Config["OutputPath"], assetsFolder)
    #destFolder = os.path.join(Config["OutputPath"], assetsFolder)
    if not os.path.exists(destFolder):
        os.makedirs(destFolder)
        for afile in os.listdir(assetsFolder):
            if (afile.find('.txt') == -1):
                shutil.copyfile(os.path.join(assetsFolder, afile), os.path.join(destFolder, afile))
            #shutil.copytree(assetsFolder, os.path.join(Config["OutputPath"], assetsFolder))
           
    pylab.__InitPylab__()
    
    
    for scanner in Global.ConsolidationScanners:
        
        if Global.GenerateIndividualScannerDShieldTopTenReports:
            IndividualDShieldTopTenPorts(scanner, html=True)

        
        for severity in Global.SeverityLevels:
            IndividualVulnerabilityReport(scanner, severity, True)
            Top5CommonVulnerabilitiesWithHosts(scanner, severity)
    
    
    
    for severity in Global.SeverityLevels:
        ConsolidatedVulnerabilitySummaryReport(severity, True)
    
    ConsolidatedUniquePortProtocolServiceReport()
    
    for word in Global.SpecialSearchReports:
        ConsolidatedKeywordReport(word, html=True)
    
    ConsolidatedUniqueOSReport(html=True)
    ConsolidatedUniqueHostsReport(True)
     
    ConsolidatedDShieldTopTenPorts(0, html=True)
    ConsolidatedDShieldTopTenPorts(1, html=True)
    
    ConsolidatedHostsWithOpenPorts(html=True)
    
    CompromisedIPsReport(html=True)

    IndScannerTop5HostsWithOpenPortsAndServices(html=True)
    ConsolidatedTop5HostsWithOpenPortsAndServices(html=True)
    
    for Keyword in Global.SpecialKeywords:
        ListIPsWithSpecialKeywords(Keyword, html=True, subnet="")
    
    print 'Done generating Network-wide reports!'
    
    print 'Generating Individual System reports...'
       
    ConsolidatedHostsWithOpenPorts(html=True, subnet="", ipwise=True)
    print 'Don generating Individual System reports!'
    
    if Global.GenerateSubnetWiseReportsAndCharts:
        print 'Generating Subnet-wide Reports!'
        
        for subnet in SubnetHostsSet:
            dirPath = os.path.join(Config["OutputPath"], subnet)
            if not os.path.exists(dirPath):
                os.makedirs(dirPath)
                       
            for scanner in Global.ConsolidationScanners:
                
                if Global.GenerateIndividualScannerDShieldTopTenReports:
                    IndividualDShieldTopTenPorts(scanner, html=True, subnet=subnet)
                    
            
                for severity in Global.SeverityLevels:
                    IndividualVulnerabilityReport(scanner, severity, html=True, subnet=subnet)
                    Top5CommonVulnerabilitiesWithHosts(scanner, severity, subnet=subnet)
                    ConsolidatedVulnerabilitySummaryReport(severity, html=True, subnet=subnet)
                    
        
            ConsolidatedUniquePortProtocolServiceReport(html=True, subnet=subnet)
            for word in Global.SpecialSearchReports:
                ConsolidatedKeywordReport(word, html=True, subnet=subnet)
            ConsolidatedUniqueOSReport(html=True, subnet=subnet)
            ConsolidatedUniqueHostsReport(html=True, subnet=subnet)
            ConsolidatedDShieldTopTenPorts(0, html=True, subnet=subnet)
            ConsolidatedDShieldTopTenPorts(1, html=True, subnet=subnet)
            ConsolidatedHostsWithOpenPorts(html=True, subnet=subnet)
        
            for Keyword in Global.SpecialKeywords:
                ListIPsWithSpecialKeywords(Keyword, html=True, subnet=subnet)
            
            
        print 'Done generating Subnet-wise reports!'
        
    print 'Done generating all reports!'
    
    
        
if __name__ == "__main__":
    pass
    """
    ReadConfigFile()
    main()
    """
    