#-----------------------------------------------------------------------------
# Name:        NessusXML.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/17
# Modified:    10/1/2009
# RCS-ID:      $Id: NessusXML.py $
# Copyright:   (c) 2006
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string, os, re
from xml.dom import minidom, Node
import time

from SqliteDatabase import *


class NessusXML:
    def __init__(self, db, reportPath, AssessDate, ScannerName="Nessus", ExcludeIPs = [], CheckDBDuplicateIP=False):
        self.root = minidom.parse(reportPath)
        #self.DBName = DBName
        self.AssessDate = AssessDate
        self.ExcludeIP = ExcludeIPs
        self.ScannerName = ScannerName
        self.HostsTable = self.ScannerName+ "Hosts"
        self.PortsTable = self.ScannerName+ "Ports"
        self.CheckDuplicateIP = CheckDBDuplicateIP
        """
        self.db = SqliteDatabase(self.DBName)
        if not self.db.OpenConnection():
            return
        """
        self.db = db
        self.PortAdded = True
        self.InitializeHostInfo()
        self.InitializeAlertInfo()
        self.InitializePortInfo()
        self.HostQuery = "insert into " + self.HostsTable + " (AssessDate, IP, Subnet, MAC, HostName, OS, "
        self.HostQuery += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
       
        self.PortQuery = "insert into " + self.PortsTable + " (AssessDate, IP, Subnet, Port, Protocol, State, "
        self.PortQuery += "Service, Description, Severity, IsTrojan, CVEID, BugtraqID, Bugtraq, "
        self.PortQuery += "OVALID, OSVDB, IAVA, MSSecurityBID, SecurityFocusBID, TopSansYear, TopSansChapter) values "
        self.PortQuery += "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        
        self.PortNameRe = re.compile(r"(.*) (\()(\d+)(/)(.*)(\))")
        self.DNSRe = re.compile(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} resolves as (.*)(\.)', re.I)
        self.OSRe = re.compile(r'(Remote operating system : )(.*)(<br/>)(Confidence Level : )(\d+)(<br/>)(.*)', re.I)
        self.RiskFactorRe = re.compile(r'(.*)(Risk Factor</b> : )(<br/>)*(High|Medium|Low)(.*)', re.I)
        self.CVERe = re.compile(r'((CVE-\d+-\d+)(,)*)', re.I)
        self.IAVARe = re.compile(r'(IAVA:)(\d+-[A-Z]-\d+)(,)*', re.I)
        self.BugtraqRe = re.compile(r'(BID : )(\d+[,]*[ ]*)+', re.I)
        self.OSVDBRe = re.compile(r'(OSVDB:)(\d)+', re.I)
        
        self.ErrorMessages = ""
        
    
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
        
    
    def InitializePortInfo(self):
        self.ServiceName = "N/A"
        self.Port = 100000
        self.Protocol = "N/A"
        self.PortState = "open"
    
    def InitializeAlertInfo(self):
        self.Description = "N/A"
        self.Severity = 0
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
        
    def parse(self):
        for host in self.root.getElementsByTagName("host"):
            self.HostIP = self.getAttribute(host, "hostname")
            self.Subnet = self.HostIP[:self.HostIP.rfind('.')]
            if self.HostIP in self.ExcludeIP:
                continue
            
            if self.CheckDuplicateIP:
               if self.HasDuplicateIP(self.HostIP):
                   continue
               
            self.MAC = "N/A"
            for port in host.getElementsByTagName("port"):
                self.TotalOpenPorts += 1
                portname = self.getAttribute(port, "portname").strip()
                match = self.PortNameRe.match(portname)
                if match:
                    self.ServiceName = match.group(1)
                    #print self.ServiceName
                    self.Port = match.group(3)
                    self.Protocol = match.group(5)
                    
                for alert in port.getElementsByTagName("alert"):
                    self.Description = self.getContent(alert.getElementsByTagName("desc")[0])
                    match = self.RiskFactorRe.match(self.Description)
                    riskFactor = "N/A"
                    factor = 0
                    if match:
                        riskFactor = match.group(4)
                        
                    if riskFactor.lower() == "high":
                        factor = 3
                        self.TotalHigh += 1
                        
                    elif riskFactor.lower() == "medium":
                        factor = 2
                        self.TotalMedium += 1
                        
                    elif riskFactor.lower() == "low":
                        self.TotalLow += 1
                        factor = 1
                        
                    else:
                        self.TotalInfo += 1
                        
                    self.Severity = factor
                    self.CVEID = self.GetREMatches(self.CVERe, self.Description)
                    match = self.BugtraqRe.search(self.Description)
                    if match:
                        self.BugtraqID  = match.group(0)
                        
                    self.OSVDB = self.GetREMatches(self.OSVDBRe, self.Description)
                    self.IAVA = self.GetREMatches(self.IAVARe, self.Description)
        
                    self.InsertPortInfo()
                    self.InitializeAlertInfo()
                    
                self.InitializePortInfo()

            for general in host.getElementsByTagName("general"):
                portname = self.getAttribute(general, "portname").strip()
                self.Port = 100000 #portname[:portname.find("/")]
                self.Protocol = portname[portname.find("/")+1:]
                #print portname
                for alert in general.getElementsByTagName("alert"):
                    ScanID = self.getContent(alert.getElementsByTagName("id")[0])
                    self.Description = self.getContent(alert.getElementsByTagName("desc")[0])
                    #print ScanID
                    if ScanID == "19506":
                        #self.inScanInfo = 1
                        continue
                    elif ScanID == "11936":
                        match = self.OSRe.match(self.Description)
                        if match:
                            self.OS = match.group(2)
                            self.ConfidenceLevel = match.group(5)
                            continue
                    elif ScanID == "12053":
                        match = self.DNSRe.match(self.Description)
                        if match:
                            self.HostName = match.group(1)
                            continue
                    else:
                        #self.Description = self.getContent(alert.getElementsByTagName("desc")[0])
                        match = self.RiskFactorRe.match(self.Description)
                        riskFactor = "N/A"
                        factor = 0
                        if match:
                            riskFactor = match.group(4)
                            
                        if riskFactor.lower().find("high") >= 0:
                            factor = 3
                            self.TotalHigh += 1
                            
                        elif riskFactor.lower().find("medium") >=0:
                            factor = 2
                            self.TotalMedium += 1
                            
                        elif riskFactor.lower().find("low") >= 0:
                            self.TotalLow += 1
                            factor = 1
                            
                        else:
                            self.TotalInfo += 1
                            
                        self.Severity = factor
                        self.InsertPortInfo()
                        self.InitializeAlertInfo()
                    
                self.InitializePortInfo()
                        
            self.InsertHostInfo()
        #self.db.CloseConnection()
        #self.db = None
        
    def getContent(self, node):
        content = []
        strContent = "N/A"
        for child in node.childNodes:
            
            if child.nodeType == Node.TEXT_NODE or child.nodeType == Node.CDATA_SECTION_NODE:
                content.append(child.data)
            if content:
                strContent = string.join(content)
        return strContent
        

    def getAttribute(self, node, att):
        attrValue = "N/A"
        attrs = node.attributes
        for attrName in attrs.keys():
            if attrName == att: 
                attrNode = attrs.get(attrName)
                attrValue = attrNode.nodeValue
        return attrValue
    
    def GetREMatches(self, regExp, desc):
        matches = "N/A"
        for word in desc.split():
            match = regExp.match(word)
            if match:
                if matches == "N/A":
                    matches = match.group(2)
                else:
                    matches += ", " + match.group(2)
        return matches

    def InsertHostInfo(self):
        HostInfo = [(self.AssessDate, self.HostIP, self.Subnet, self.MAC, self.HostName, self.OS, self.OSVersion, 
            self.ConfidenceLevel, self.TotalHigh, self.TotalMedium, self.TotalLow,
            self.TotalInfo, self.TotalOpenPorts, self.TotalFilteredPorts)]

        #print self.HostQuery + query
        try:
            
            #self.db.ExecuteNonQuery(self.HostQuery + query)
            self.db.ExecuteMany(self.HostQuery, HostInfo)
            #print self.HostQuery, query
        except Exception, value:
            self.ErrorMessages += "Error: Message" + str(value) + "\n"
        self.InitializeHostInfo()
        

    def InsertPortInfo(self):
        PortInfo = [(self.AssessDate, self.HostIP, self.Subnet, self.Port, self.Protocol, self.PortState, self.ServiceName,
            self.Description, self.Severity, self.IsTrojan, self.CVEID, self.BugtraqID, self.Bugtraq,
            self.OVALID, self.OSVDB, self.IAVA, self.MSSecurityBID, self.SecurityFocusBID, self.TopSansYear, self.TopSansChapter)]
        
        try:
            self.db.ExecuteMany(self.PortQuery, PortInfo)   
        except Exception, value:
            print str(value)
            self.ErrorMessages += "Error: Message" + str(value) + "\n"
            
            
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
        query = "DROP TABLE IF EXISTS NessusHosts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `NessusHosts`(
        `AssessDate` integer,
        `IP` varchar(20),
        `Subnet` varchar(20),
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
        query = "DROP TABLE IF EXISTS NessusPorts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `NessusPorts`(
        `AssessDate` integer,
        `IP` varchar(20),
        `Subnet` varchar(20),
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
    reportPath = "./NessusReports/164.64.9.175.xml"
    InitTables("Test.db", True)
    parser = NessusXML("Test.db", reportPath, time.time())
    parser.parse()