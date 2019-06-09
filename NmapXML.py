#-----------------------------------------------------------------------------
# Name:        NmapXML.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/17
# RCS-ID:      $Id: NmapXML.py $
# Copyright:   (c) 2006
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string
import xml.sax
import time

from SqliteDatabase import *

class NmapXML:
    def __init__(self, db, reportPath, AssessDate, Scanner='Nmap', ExcludeIP = [], CheckDBDuplicateIP=False):
        self.parser = xml.sax.make_parser()
        self.handler = NmapXMLHandler(db, AssessDate, Scanner, ExcludeIP, CheckDBDuplicateIP)
        self.parser.setContentHandler(self.handler)
        self.reportPath = reportPath
        
    def parse(self):
        self.parser.parse(self.reportPath)
        #self.handler.db.CloseConnection()
        

class NmapXMLHandler(xml.sax.handler.ContentHandler):
    def __init__(self, db, AssessDate, Scanner, ExcludeIP, CheckDBDuplicateIP):
        
        #self.DBName = DBName
        self.Scanner = Scanner
        self.HostsTable = self.Scanner + "Hosts"
        self.PortsTable = self.Scanner + "Ports"
        self.AssessDate = AssessDate
        self.ExcludeIP = ExcludeIP
        self.CheckDuplicateIP = CheckDBDuplicateIP
        #self.RunTable = "N/A"
        #self.RunID = "N/A"
        #self.db = SqliteDatabase(self.DBName)
        self.IsProject = True
        
        #if not self.db.OpenConnection():
        #    return
        self.db = db
        self.InitializeHostInfo()
        self.HostQuery = "insert into " + self.HostsTable + " (AssessDate, IP, Subnet, MAC, HostName, OS, "
        self.HostQuery += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
       
        self.PortQuery = "insert into " + self.PortsTable + " (AssessDate, IP, Subnet, Port, Protocol, State, "
        self.PortQuery += "Service, Description, Severity, IsTrojan, CVEID, BugtraqID, Bugtraq, "
        self.PortQuery += "OVALID, OSVDB, IAVA, MSSecurityBID, SecurityFocusBID, TopSansYear, TopSansChapter) values "
        self.PortQuery += "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
         
        self.ErrorMessages = ""
        
        
    def InitializeHostInfo(self):
        self.inHost = 0
        self.inPorts = 0
        self.inPort = 0
        self.inOS = 0
        
        #self.inStatus = 0
        self.HostName = "N/A"
        self.HostIP = "N/A"
        self.Subnet = "N/A"
        self.HostState = ""
        self.IPType = ""
        self.OS = []
        self.OSVendor = "N/A"
        self.OSFamily = []
        self.OSVersion = []
        self.MAC = "N/A"
        self.HWVendor = "N/A"
        self.UpTime = 0
        self.LastBoot = ""
        self.InRunStats = 0
        self.ConfidenceLevel = []
        self.TotalInfo = 0
        self.TotalLow = 0
        self.TotalHigh = 0
        self.TotalOpenPorts = 0
        self.TotalFilteredPorts = 0
        self.TotalMedium = 0
        self.InitPorts()
        
    def InitPorts(self):
        self.ServiceName = "N/A"
        self.Port = 100000
        self.Protocol = "N/A"
        self.PortState = "open"
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
        
        
    def startElement(self, name, attributes):
        if name == "nmaprun":
            self.Command = attributes["args"]
            self.StartSeconds = attributes["start"]
            self.NmapStartTime = attributes["startstr"]
            self.NmapVersion = attributes["version"]
        elif name == "scaninfo":
            self.ScanType = attributes["type"]
            self.Protocol = attributes["protocol"]
            self.NumServices = attributes["numservices"]
        elif name == "host":
            #self.Initialize()
            self.inHost = 1
        
        elif name == "status":
            if self.inHost:
                self.HostState = attributes["state"]
        elif name == "address":
            addrtype = attributes['addrtype']
            if addrtype == 'mac':
                #if attributes.has_key("vendor") and not attributes.has_key('addrtype'):
                mac = attributes["addr"]
                self.MAC = mac.replace(':', '-')
                
            else: #attributes.has_key("addrtype"):
                self.HostIP = attributes["addr"]
                self.Subnet = self.HostIP[:self.HostIP.rfind('.')]
                self.IPType = attributes["addrtype"]
        elif name == "hostname":
            if attributes["type"] == "PTR":
                self.HostName = attributes["name"]
        elif name == "ports":
            self.inPorts = 1
               
        elif name == "port":
            self.inPort = 1
            self.Protocol = attributes["protocol"]
            self.Port = attributes["portid"]
            self.TotalOpenPorts += 1
        elif name == "state":
            if self.inPort:
                self.PortState = attributes["state"]
        elif name == "service":
            if self.inPort:
                self.ServiceName = attributes["name"]
                if attributes.has_key("product"):
                    self.Product = attributes["product"]
                if attributes.has_key("version"):
                    self.ProductVersion = attributes["version"]
        elif name == "os":
            self.inOS = 1
        elif name == "osclass":
            if self.inOS:
                self.OSFamily.append(attributes["osfamily"])
            if attributes.has_key("osgen"):
                self.OSVersion.append(attributes["osgen"])
        elif name == "osmatch":
            if self.inOS:
                self.OS.append(attributes["name"])
                self.ConfidenceLevel.append(attributes["accuracy"])
        elif name == "uptime":
            self.UpTime = attributes["seconds"]
            self.LastBoot = attributes["lastboot"]
        elif name == "runstats":
            self.InRunStats = 1
        elif name == "finished":
            if self.InRunStats:
                self.FinishedSeconds = attributes["time"]
                self.NmapFinishedTime = attributes["timestr"]
        elif name == "hosts":
            if self.InRunStats:
                self.TotalHostsUp = attributes["up"]
                self.TotalHostsDown = attributes["down"]
                self.TotalHosts = attributes["total"]
 
            
    def endElement(self, name):
        if name == "port":
            self.inPort = 0
            if self.HostIP in self.ExcludeIP:
                self.InitPorts()
                return
            
            if self.CheckDuplicateIP:
                if self.HasDuplicateIP(self.HostIP):
                    self.InitPorts()
                    return
                
            self.InsertPortInfo()
            self.InitPorts()
            
            
        elif name == "host":
            if self.HostIP in self.ExcludeIP:
                self.InitializeHostInfo()
                return
                
            if self.CheckDuplicateIP:
                if self.HasDuplicateIP(self.HostIP):
                    self.InitializeHostInfo()
                    return
                
            self.InsertHostInfo()
            
        elif name == "nmaprun":
            #self.db.CloseConnection()
            pass
        elif name == "os":
            self.inOS = 0
            
    
    def GetErrorMessages(self):
        if self.ErrorMessages == "":
            self.ErrorMessages = "Nmap xml output parsing finished with 0 error.\n"
            
        return self.ErrorMessages
    
    def HasDuplicateIP(self, ip):
        query = "select count(*) from " + self.HostsTable + " where IP='" + ip + "';"
        row = self.db.FetchOneRow(query)
        if int(row[0]) > 0:
            return True
        else:
            return False
    
    def InsertHostInfo(self):
        HostInfo = [(self.AssessDate, self.HostIP, self.Subnet, self.MAC, self.HostName, string.join(self.OS, '; '), string.join(self.OSVersion, '; '), 
            string.join(self.ConfidenceLevel, '; '), self.TotalHigh, self.TotalMedium, self.TotalLow,
            self.TotalInfo, self.TotalOpenPorts, self.TotalFilteredPorts)]
        
        #print self.HostQuery + query
        try:
            #print self.HostQuery, query
            #self.db.ExecuteNonQuery(self.HostQuery + query)
            self.db.ExecuteMany(self.HostQuery, HostInfo)
            
        except Exception, value:
            print str(value)
            
            self.ErrorMessages += "Error: Message" + str(value) + "\n"
        self.InitializeHostInfo()
        

    def InsertPortInfo(self):
        PortInfo = [(self.AssessDate, self.HostIP, self.Subnet, self.Port, self.Protocol, self.PortState, self.ServiceName,
            self.Description, self.Severity, self.IsTrojan, self.CVEID, self.BugtraqID, self.Bugtraq,
            self.OVALID, self.OSVDB, self.IAVA, self.MSSecurityBID, self.SecurityFocusBID, self.TopSansYear, self.TopSansChapter)]
        
               
        try:
            #insert into database
            #print self.PortQuery + PortQuery
            #self.db.ExecuteNonQuery(self.PortQuery + query)
            self.db.ExecuteMany(self.PortQuery, PortInfo)   
        except Exception, value:
            print str(value)
            self.ErrorMessages += "Error: Message" + str(value) + "\n"
            
def InitTables(DBName, dropTable=False):
    db = SqliteDatabase(DBName)
    if not db.OpenConnection():
        return None
    #Hosts table
    if dropTable:
        query = "DROP TABLE IF EXISTS NmapHosts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `NmapHosts`(
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
        FilteredPorts integer
        );
    """
    db.ExecuteNonQuery(query)

    #Ports table
    if dropTable:
        query = "DROP TABLE IF EXISTS NmapPorts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `NmapPorts`(
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
        

if __name__ == '__main__':
    InitTables('Test.db', True)
    nmapParser = NmapXML("Test.db", "./NmapReports/nmap.xml", time.time(), 'Nmap', [], True)
    nmapParser.parse()
    
