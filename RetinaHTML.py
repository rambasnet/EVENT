#-----------------------------------------------------------------------------
# Name:        RetinaHTML.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/17
# RCS-ID:      $Id: RetinaHTML.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string, re
import time
from stat import *

from SqliteDatabase import *


class RetinaHTML:
    def __init__(self, db, reportPath, AssessDate, Scanner="Retina", ExcludeIP=[], CheckDBDuplicateIP=False):
        self.reportPath = reportPath
        #self.DBName = DBName
        self.AssessDate = AssessDate
        self.ExcludeIP = ExcludeIP
        self.HostsTable = "RetinaHosts"
        self.PortsTable = "RetinaPorts"
        self.CheckDuplicateIP = CheckDBDuplicateIP
        self.FirstAddressFound = False
        self.PreviousIP = "N/A"
        """
        self.db = SqliteDatabase(self.DBName)
        if not self.db.OpenConnection():
            return
        """
        self.db = db
        self.PortAdded = True
        self.InitializeHostInfo()
        self.InitializePortInfo()
        self.RegisterRegularExpressions()
        self.HostQuery = "insert into " + self.HostsTable + " (AssessDate, IP, Subnet, MAC, HostName, OS, "
        self.HostQuery += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts) values ("
       
        self.PortQuery = "insert into " + self.PortsTable + " (AssessDate, IP, Subnet, Port, Protocol, State, "
        self.PortQuery += "Service, Description, Severity, IsTrojan, CVEID, BugtraqID, Bugtraq, "
        self.PortQuery += "OVALID, OSVDB, IAVA, MSSecurityBID, SecurityFocusBID, TopSansYear, TopSansChapter) values ("
        self.ErrorMessages =""
    
    def InitializeHostInfo(self):
        self.HostIP = "N/A"
        self.Subnet = "N/A"
        self.MAC = "N/A"
        self.HostName = "N/A"
        self.OS = "N/A"
        self.OSVersion = "N/A"
        self.ConfidenceLevel = 0
        self.TotalInfo = 0
        self.TotalLow = 0
        self.TotalHigh = 0
        self.TotalOpenPorts = 0
        self.TotalFilteredPorts = 0
        self.TotalMedium = 0
        self.PreviousPort = 0
        self.InAudits = False
        self.InPorts = False
        self.InMachine = False
        
    
    def InitializePortInfo(self):
        self.ServiceName = "N/A"
        self.Port = 100000
        self.Protocol = "N/A"
        self.PortState = "open"
        self.Description = "N/A"
        self.Severity = 0
        self.ScanID = "N/A"
        self.IsTrojan  = 0
        self.CVEID = "N/A"
        self.BugtraqID = "N/A"
        self.Bugtraq = "N/A"
        self.MSSecurityBID = "N/A"
        self.OVALID = "N/A"
        self.OSVDB = "N/A"
        self.IAVA = "N/A"
        self.SecurityFocusBID = "N/A"
        self.TopSansYear = "N/A"
        self.TopSansChapter = "N/A"
        
        
    def RegisterRegularExpressions(self):
        self.AddressIPRe = re.compile(r'<FONT FACE=Arial SIZE=4><B>Address (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})</B></FONT>.*')
        self.AuditsRe = re.compile(r'<B><FONT FACE=Arial Size=4>Audits: (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})</Font></B><BR>', re.I)
        
        self.OSRe = re.compile(r'<B><FONT FACE=Arial Size=3>OS Detected: (.*)</Font></B><BR>', re.I)
        #regex2 = '<B><FONT FACE=Arial Size=3>.*: (((TCP|UDP):(\d+))|.*).*</Font></B><BR>'
        #self.NonPortRe = re.compile('<B><FONT FACE=Arial Size=3>.*: (((TCP|UDP):(\d+))|.*).*</Font></B><BR>', re.I)
        self.NonPortVulnRe = re.compile('<B><FONT FACE=Arial Size=3>.*: (.*)</Font></B><BR>', re.I)
        self.PortVulnRe = re.compile(r'<B><FONT FACE=Arial Size=3>.*: (TCP|UDP):(\d+)( - )*([a-z0-9]*)( - )*(.*)</Font></B><BR>', re.I)

        #regex3 = '<B>Risk Level: (High|Medium|Low|Information)</B> <BR>'
        self.SeverityRe = re.compile(r'<B>Risk Level: (High|Medium|Low|Information)</B> <BR>', re.I)

        #regex4 = '<B>Description:</B> (.*)<BR>'
        self.DescriptionRe = re.compile(r'<B>Description:</B> (.*)<BR>', re.I)

        #regex5 = '<B>CVE: </B> <A href="http://cve.mitre.org/cgi-bin/cvename.cgi\?name=.*" target="_default">(.*)</A> <BR>'
        self.CVERe = re.compile(r'<B>CVE: </B> <A href="http://cve.mitre.org/cgi-bin/cvename.cgi\?name=.*" target="_default">(.*)</A>', re.I)
        self.BugtraqIDRe = re.compile(r'<B>BugtraqID: </B> <A href="http://www.securityfocus.com/bid/.*" target="_default">(.*)</A>', re.I)
        #regex6 = '<B><FONT FACE=Arial Size=4>Machine: ' + ip_heading + '</Font></B><BR>'
        self.MachineRe = re.compile(r'<B><FONT FACE=Arial Size=4>Machine: (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})</Font></B><BR>', re.I)

        #regex7 = '<B><FONT FACE=Arial Size=4>Ports: ' + ip_heading + '</Font></B><BR>'
        self.PortsRe = re.compile(r'<B><FONT FACE=Arial Size=4>Ports: (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})</Font></B><BR>', re.I)

        #regex8 = '<B><FONT FACE=Arial Size=3>(\d+): (.*) - (.*)</Font></B><BR>'
        self.PortRe = re.compile(r'<B><FONT FACE=Arial Size=3>(\d+): (.*) - (.*)</Font></B><BR>', re.I)
        self.VersionRe = re.compile(r'<B>Version: </B> (.*)(<BR>)*', re.I)
        #regex9 = '<B>Detected Protocol: </B> (.*)<BR>'
        #r9 = re.compile(r'<B>Detected Protocol: </B> (.*)<BR>', re.I)

        #regex10 = '<B>Port State: </B> (Open|Filtered|Closed)<BR>'
        self.PortStateRe = re.compile(r'<B>Port State: </B> (Open|Filtered|Closed)<BR>', re.I)
        
        self.LineImageRe = re.compile(r'<IMG SRC="images/black.gif" width=100% height=1 VSPACE=3><BR>', re.I)
        self.FilteredPortsRe = re.compile(r'<B><FONT FACE=Arial Size=3>Filtered Ports: (\d+)</Font></B><BR>', re.I)
        self.OpenPortsRe = re.compile(r'<B><FONT FACE=Arial Size=3>Open Ports: (\d+)</Font></B><BR>', re.I)
        #regex11 = '<FONT FACE=Arial SIZE=4><B>Address \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}</B></FONT>'
        #r11 = re.compile(regex11)
        
    def parse(self):
        f = open(self.reportPath, "r")
        data = f.readlines()

        for line in data:
            if not self.FirstAddressFound:
            #first get to the first address line
                match = self.AddressIPRe.search(line)
                if match:
                    ip = match.group(1)
                    tmp = ip.split(".")
                    newNums = []
                    for num in tmp:
                        newNums.append(str(int(num)))
                        
                    self.HostIP = string.join(newNums, ".")
                    self.Subnet = self.HostIP[:self.HostIP.rfind('.')]
                    if not self.HostIP in self.ExcludeIP:
                    #self.PreviousIP = self.HostIP
                        if self.CheckDuplicateIP:
                            if not self.HasDuplicateIP(self.HostIP):
                                self.FirstAddressFound = True
                        else:
                            self.FirstAddressFound = True
            else:
                #check for other info
                #if not self.InAudits:
                if self.InAudits:
                    #now in audits section
                    #self.InAudits = True
                    match = self.PortVulnRe.search(line)
                    if match:
                        #check if the previous port/vulnerability info is added to db
                        if not self.PortAdded:
                            #add ports in db
                            self.InsertPortInfo()
                            #self.PortAdded = False
                            
                        self.Port = match.group(2)
                        self.Protocol = match.group(1)
                        if not match.group(4) == "":
                            self.ServiceName = match.group(4)
                        continue
                    
                    match = self.NonPortVulnRe.search(line)
                    if match:
                        if not self.PortAdded:
                            #add ports in db
                            self.InsertPortInfo()
                            #self.PortAdded = False
                        """ 
                        self.Port = match.group(2)
                        self.Protocol = match.group(1)
                        if not match.group(4) == "":
                            self.ServiceName = match.group(4)
                        """
                        self.ServiceName = match.group(1)
                        continue
                        
                    match = self.SeverityRe.search(line)
                    if match:
                        severity = match.group(1)
                        if severity.lower() == "High".lower():
                            self.Severity = 3
                            self.TotalHigh += 1
                        elif severity.lower() == "Medium".lower():
                            self.Severity = 2
                            self.TotalMedium += 1
                        elif severity.lower() == "Low".lower():
                            self.Severity = 1
                            self.TotalLow += 1
                        else:
                            self.TotalInfo += 1
                        continue
                    
                    match = self.DescriptionRe.search(line)
                    if match:
                        self.Description = match.group(1)
                        self.PortAdded = False
                        continue
                    
                    match = self.CVERe.search(line)
                    if match:
                        self.CVEID = match.group(1)
                        self.PortAdded = False
                        continue
                    
                    match = self.BugtraqIDRe.search(line)
                    if match:
                        self.BugtraqID = match.group(1)
                        self.InsertPortInfo()
                        continue
                        
                    #self.InAudits = False
                    #check if we have come across different section
                    match = self.MachineRe.search(line)
                    if match:
                        if not self.PortAdded:
                            self.InsertPortInfo()
                            
                        self.InMachine = True
                        self.InAudits = False
                        self.InPorts = False
                        
                        
                elif self.InMachine:
                    match = self.OSRe.search(line)
                    if match:
                        self.OS = match.group(1)
                        continue
                    match = self.FilteredPortsRe.search(line)
                    if match:
                        self.TotalFilteredPorts = match.group(1)
                        continue
                    match = self.OpenPortsRe.search(line)
                    if match:
                        self.TotalOpenPorts = match.group(1)
                        continue
                    
                    match = self.PortsRe.search(line)
                    if match:
                        self.InMachine = False
                        self.InPorts = True
                        
                elif self.InPorts:
                    match = self.PortRe.search(line)
                    if match:
                        if not self.PortAdded:
                            self.PortAdded = False
                            self.InsertPortInfo()
                            
                        self.Port = match.group(1)
                        self.ServiceName = match.group(2)
                        continue
                    match = self.PortStateRe.search(line)
                    if match:
                        self.PortState = match.group(1).lower()
                        self.PortAdded = False
                        continue
                    match = self.VersionRe.search(line)
                    if match:
                        self.Description = match.group(1)
                        self.InsertPortInfo()
                        continue
                    
                    match = self.AddressIPRe.search(line)
                    if match:
                        if not self.PortAdded:
                            self.PortAdded = True
                            self.InsertPortInfo()
                            
                        self.InsertHostInfo()
                        ip = match.group(1)
                        tmp = ip.split(".")
                        newNums = []
                        for num in tmp:
                            newNums.append(str(int(num)))
                            
                        self.HostIP = string.join(newNums, ".")
                        self.Subnet = self.HostIP[:self.HostIP.rfind('.')]
                        if not self.HostIP in self.ExcludeIP:
                            #if not self.HostIP == self.PreviousIP:
                            if self.CheckDuplicateIP:
                                if not self.HasDuplicateIP(self.HostIP):
                                    self.InAudits = False
                                    self.InPorts = False
                                    self.InMachine = False
                            else:
                                self.InAudits = False
                                self.InPorts = False
                                self.InMachine = False
                                
                            #new host found
                            #update host database
                            
                        #self.PreviousIP = self.HostIP
                    
                    
                else:
                    match = self.AuditsRe.search(line)
                    if match:
                        self.InMachine = False
                        self.InPorts = False
                        self.InAudits = True
        
        if not self.PortAdded:
            #self.PortAdded = True
            self.InsertPortInfo()
        self.InsertHostInfo()
        
            
    def InsertHostInfo(self):
        query = str(self.AssessDate) + "," + self.db.SqlSQuote(self.HostIP) + "," + self.db.SqlSQuote(self.Subnet) + "," + self.db.SqlSQuote(self.MAC) + ","
        query += self.db.SqlSQuote(self.HostName) + "," + self.db.SqlSQuote(self.OS) + "," + self.db.SqlSQuote(self.OSVersion) + ","
        query += str(self.ConfidenceLevel) + "," + self.db.SqlSQuote(self.TotalHigh) + "," + self.db.SqlSQuote(self.TotalMedium) + ","
        query += self.db.SqlSQuote(self.TotalLow) + "," + str(self.TotalInfo) + "," + self.db.SqlSQuote(self.TotalOpenPorts) + ","
        query += str(self.TotalFilteredPorts) + ")"
        #print self.HostQuery + query
        try:
            self.db.ExecuteNonQuery(self.HostQuery + query)
            #print self.HostQuery, query
        except Exception, value:
            self.ErrorMessages += "Error: Message" + str(value) + "\n"
        self.InitializeHostInfo()
        

    def InsertPortInfo(self):
        query = str(self.AssessDate) + "," + self.db.SqlSQuote(self.HostIP) + "," + self.db.SqlSQuote(self.Subnet) + ","
        query += self.db.SqlSQuote(self.Port) + "," + self.db.SqlSQuote(self.Protocol) + ","
        query += self.db.SqlSQuote(self.PortState) + "," + self.db.SqlSQuote(self.ServiceName) + "," + self.db.SqlSQuote(self.Description) + ","
        query += str(self.Severity) + "," + str(self.IsTrojan) + "," + self.db.SqlSQuote(self.CVEID) + ","
        query += self.db.SqlSQuote(self.BugtraqID) + "," + self.db.SqlSQuote(self.Bugtraq) + ","
        query += self.db.SqlSQuote(self.OVALID) + "," + self.db.SqlSQuote(self.OSVDB) + ","
        query += self.db.SqlSQuote(self.IAVA) + "," + self.db.SqlSQuote(self.MSSecurityBID) + ","
        query += self.db.SqlSQuote(self.SecurityFocusBID) + "," + self.db.SqlSQuote(self.TopSansYear) + ","
        query += self.db.SqlSQuote(self.TopSansChapter) + ")"
        try:
            #insert into database
            #print self.PortQuery + query
            self.db.ExecuteNonQuery(self.PortQuery + query)
                
        except Exception, value:
            print str(value)
            self.ErrorMessages += "Error: Message" + str(value) + "\n"
            
        self.PortAdded = True
        self.InitializePortInfo()
        
    def HasDuplicateIP(self, ip):
        query = "select count(*) from " + self.HostsTable + " where IP='" + ip + "';"
        row = self.db.FetchOneRow(query)
        if int(row[0]) > 0:
            return True
        else:
            return False
    
def InitTables(DBName, dropTable=False):
    db = SqliteDatabase(DBName)
    if not db.OpenConnection():
        return None
    #Hosts table
    if dropTable:
        query = "DROP TABLE IF EXISTS RetinaHosts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `RetinaHosts`(
        `AssessDate` integer,
        `IP` varchar(20),
        `MAC` varchar (32),
        `HostName` varchar(200),
        `OS` text,
        `OSVersion` varchar(100),
        `ConfidenceLevel` integer,
        `High` integer,
        `Medium` integer,
        `Low` integer,
        `Info` integer,
        `OpenPorts` integer,
        `FilteredPorts` integer
        );
    """
    db.ExecuteNonQuery(query)

    #Ports table
    if dropTable:
        query = "DROP TABLE IF EXISTS RetinaPorts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `RetinaPorts`(
        `AssessDate` integer,
        `IP` varchar(20),
        `Port` integer,
        `Protocol` varchar(10),
        `State` varchar(10),
        `Service` varchar(50),
        `Description` text,
        `Severity` integer,
        `IsTrojan` integer,
        `CVEID` text,
        `BugtraqID` text,
        `Bugtraq` text,
        `OVALID` text,
        `OSVDB` text,
        `IAVA` text,
        `MSSecurityBID` text,
        `SecurityFocusBID` text,
        `TopSansYear` text,
        `TopSansChapter` text,
        `IsFalsePositive` integer
        );
        """
    db.ExecuteNonQuery(query)
    db.CloseConnection()


if __name__ == "__main__":
    dbName = "Test.db"
    retinaParser = RetinaHTML(dbName, "./WorkForce/RetinaReports/164.64.31.[1-255]/164.64.31.[1-255].html", time.time(), "Retina", [], True)
    InitTables(dbName, True)
    retinaParser.parse()