#-----------------------------------------------------------------------------
# Name:        LanguardXML.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/17
# RCS-ID:      $Id: LanguardXML.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------


import sys, string, os, re
from xml.dom import minidom, Node
import time

from SqliteDatabase import *

class LanguardXML:
    def __init__(self, db, reportPath, AssessDate, Scanner="Languard", ExcludeIP = [], CheckDBDuplicateIP=False):
        self.root = minidom.parse(reportPath)
        #self.DBName = DBName
        self.AssessDate = AssessDate
        self.Scanner = Scanner
        self.ExcludeIP = ExcludeIP
        self.HostsTable = self.Scanner + "Hosts"
        self.PortsTable = self.Scanner + "Ports"
        self.CheckDuplicateIP = CheckDBDuplicateIP
        self.db = db
        """
        self.db = SqliteDatabase(self.DBName)
        
        if not self.db.OpenConnection():
            return
        """
        self.PortAdded = True
        self.InitializeHostInfo()
        self.InitializePortInfo()
        self.HostQuery = "insert into " + self.HostsTable + " (AssessDate, IP, Subnet, MAC, HostName, OS, "
        self.HostQuery += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
       
        self.PortQuery = "insert into " + self.PortsTable + " (AssessDate, IP, Subnet, Port, Protocol, State, "
        self.PortQuery += "Service, Description, Severity, IsTrojan, CVEID, BugtraqID, Bugtraq, "
        self.PortQuery += "OVALID, OSVDB, IAVA, MSSecurityBID, SecurityFocusBID, TopSansYear, TopSansChapter) values "
        self.PortQuery += "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        
        self.ServiceRe = re.compile(r'([\w -]+)+(, | => )*(.*)', re.I)
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
        
    def parse(self):
        for host in self.root.getElementsByTagName("host"):
            self.HostIP = self.getContent(host.getElementsByTagName("ip")[0])
            self.Subnet = self.HostIP[:self.HostIP.rfind('.')]
            if self.HostIP in self.ExcludeIP:
                continue
            
            if self.CheckDuplicateIP:
                if self.HasDuplicateIP(self.HostIP):
                    continue
            
            self.MAC = self.getContent(host.getElementsByTagName("mac")[0])
            self.HostName = self.getContent(host.getElementsByTagName("hostname")[0])
            self.OS = self.getContent(host.getElementsByTagName("os")[0])
            for ports in host.getElementsByTagName("ports"):
                for tcp_port in ports.getElementsByTagName("port"):
                    self.TotalOpenPorts += 1
                    #service = self.getAttribute(tcp_port, "service").strip()
                    desc = self.getAttribute(tcp_port, "desc")
                    #if not service:
                    match = self.ServiceRe.search(desc)
                    if match:
                        self.ServiceName = match.group(1)
                        self.Description = match.group(3)
                    else:
                        self.ServiceName = desc
                        self.Description = desc
                    #if service:
                    #    self.ServiceName = service
                        
                    self.Port = self.getAttribute(tcp_port, "name")
                    self.Protocol = "TCP"
                    self.IsTrojan = int(self.getAttribute(tcp_port, "isTrojan").strip())
                    #list is: severityLevel, description, bugtraq, ovalid, cveid, 
                    #mssecuritybid, securityfocusbid, TopSansYear, Topsanschapter
                    self.AssociatePortWithAlerts(host)
                    self.InitializePortInfo()

            for ports in host.getElementsByTagName("udp_ports"):
                for udp_port in ports.getElementsByTagName("port"):
                    #try:
                    desc = self.getAttribute(udp_port, "desc")
                    match = self.ServiceRe.search(desc)
                    self.TotalOpenPorts += 1
                    if match:
                        self.ServiceName = match.group(1)
                        self.Description = match.group(3)
                        if not self.Description:
                            self.Description = self.ServiceName
                    else:
                        self.Description = desc
                        self.ServiceName = desc
                    #if service:
                    #    self.ServiceName = service
                        
                    self.Port = int(self.getAttribute(udp_port, "name").strip())
                    self.Protocol = "UDP"
                    self.IsTrojan = int(self.getAttribute(udp_port, "isTrojan").strip())
                    #list is: severityLevel, description, bugtraq, ovalid, cveid, 
                    #mssecuritybid, securityfocusbid, TopSansYear, Topsanschapter
                    self.AssociatePortWithAlerts(host)
                    self.InitializePortInfo()
                    #except:
                    #    pass
                    
            self.AddRemainingAlerts(host)
            self.InsertHostInfo()
                    
    def AddRemainingAlerts(self, hostNode):
        for severity in hostNode.getElementsByTagName("severity"):
            severityLevel = int(self.getAttribute(severity, "level").strip()) + 1
            for alert in severity.getElementsByTagName("alert"):
                self.Description = self.getContent(alert.getElementsByTagName("name")[0])
                self.Description += " " + self.getContent(alert.getElementsByTagName("descr")[0])
                #details = self.getContent(alert.getElementsByTagName("details")[0])
                self.Severity = severityLevel
                if self.Severity == 1:
                    self.TotalLow += 1
                elif self.Severity == 2:
                    self.TotalMedium += 1
                elif self.Severity == 3:
                    self.TotalHigh += 1
                    
                self.Bugtraq = self.getContent(alert.getElementsByTagName("bugtraq")[0])
                self.OVALID = self.getContent(alert.getElementsByTagName("OVAL_ID")[0])
                self.CVEID = self.getContent(alert.getElementsByTagName("CVE_ID")[0])
                self.MSSecurityBID = self.getContent(alert.getElementsByTagName("MS_Security_BID")[0])
                self.SecurityFocusID = self.getContent(alert.getElementsByTagName("Security_Focus_BID")[0])
                self.TopSansYear = self.getContent(alert.getElementsByTagName("TopSansYear")[0])
                self.TopSansChapter = self.getContent(alert.getElementsByTagName("TopSansChapter")[0])
                #list is: severityLevel, description, bugtraq, ovalid, cveid, 
                #mssecuritybid, securityfocusbid, TopSansYear, Topsanschapter
                #alertInfo = [severityLevel, descr, Bugtraq, OvalID, CVEID, MSSecurityID, SecurityFocusID, TopSansYear, TopSansChapter]
                #AlertList.append(alertInfo)
                self.InsertPortInfo()
                self.InitializePortInfo()
                #servicesAlert.removeChild(alert)

    def AssociatePortWithAlerts(self, hostNode):
        #AlertList = []
        added = False
        for severity in hostNode.getElementsByTagName("severity"):
            severityLevel = int(self.getAttribute(severity, "level").strip()) + 1
            if self.IsTrojan:
                for backdoors in severity.getElementsByTagName("backdoors"):
                    for backdoor in backdoors.getElementsByTagName("backdoor"):
                        bdoor = self.getContent(backdoor)
                        if bdoor.find(str(self.Port)) >= 0 or bdoor.lower().find(self.ServiceName.lower()) >= 0:
                            #list is: severityLevel, description, bugtraq, ovalid, cveid, 
                            #mssecuritybid, securityfocusbid, TopSansYear, Topsanschapter
                            #alert = [severityLevel, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]
                            #AlertList.append(alert)
                            self.Description += " " + bdoor
                            self.Severity = severityLevel
                            if self.Severity == 1:
                                self.TotalLow += 1
                            elif self.Severity == 2:
                                self.TotalMedium += 1
                            elif self.Severity == 3:
                                self.TotalHigh += 1
                            self.CVEID = "N/A"
                            self.BugtraqID = "N/A"
                            self.Bugtraq = "N/A"
                            self.MSSecurityBID = "N/A"
                            self.OVALID = "N/A"
                            self.SecurityFocusBID = "N/A"
                            self.TopSansYear = "N/A"
                            self.TopSansChapter = "N/A"
        
                            self.InsertPortInfo()
                            added = True
                            backdoors.removeChild(backdoor)
                                
        
            for servicesAlert in severity.getElementsByTagName("Services_Alerts"):
                added = added or self.AssociateAlerts(servicesAlert, severityLevel)
                        
            for informationAlert in severity.getElementsByTagName("Information_Alerts"):
                added = added or self.AssociateAlerts(informationAlert, severityLevel)
             
            for mailAlert in severity.getElementsByTagName("Mail_Alerts"):
                added = added or  self.AssociateAlerts(mailAlert, severityLevel)
            
                   
        if not added:
            self.InsertPortInfo()

    def AssociateAlerts(self, parentNode, severityLevel):
        added = False
        for alert in parentNode.getElementsByTagName("alert"):
            vulnName = self.getContent(alert.getElementsByTagName("name")[0])
            descr = self.getContent(alert.getElementsByTagName("descr")[0])
            if vulnName.find(str(self.Port)) >= 0 or vulnName.lower().find(self.ServiceName.lower()) >= 0 or descr.find(str(self.Port)) >=0 or descr.lower().find(self.ServiceName.lower()) >= 0:
                #details = self.getContent(alert.getElementsByTagName("details")[0])
                self.Description += " " + vulnName + " " + descr
                self.Severity = severityLevel
                if self.Severity == 1:
                    self.TotalLow += 1
                elif self.Severity == 2:
                    self.TotalMedium += 1
                elif self.Severity == 3:
                    self.TotalHigh += 1
                self.Bugtraq = self.getContent(alert.getElementsByTagName("bugtraq")[0])
                self.OVALID = self.getContent(alert.getElementsByTagName("OVAL_ID")[0])
                self.CVEID = self.getContent(alert.getElementsByTagName("CVE_ID")[0])
                self.MSSecurityBID = self.getContent(alert.getElementsByTagName("MS_Security_BID")[0])
                self.SecurityFocusID = self.getContent(alert.getElementsByTagName("Security_Focus_BID")[0])
                self.TopSansYear = self.getContent(alert.getElementsByTagName("TopSansYear")[0])
                self.TopSansChapter = self.getContent(alert.getElementsByTagName("TopSansChapter")[0])
                #list is: severityLevel, description, bugtraq, ovalid, cveid, 
                #mssecuritybid, securityfocusbid, TopSansYear, Topsanschapter
                #alertInfo = [severityLevel, descr, Bugtraq, OvalID, CVEID, MSSecurityID, SecurityFocusID, TopSansYear, TopSansChapter]
                #AlertList.append(alertInfo)
                self.InsertPortInfo()
                added = True
                parentNode.removeChild(alert)
        return added
    
        
    def getContent(self, node):
        content = []
        strContent = "N/A"
        for child in node.childNodes:
            if child.nodeType == Node.TEXT_NODE:
                content.append(child.nodeValue)
            if content:
                strContent = string.join(content)
        return strContent

    def getAttribute(self, node, att):
        attrValue = ""
        attrs = node.attributes
        for attrName in attrs.keys():
            if attrName == att: 
                attrNode = attrs.get(attrName)
                attrValue = attrNode.nodeValue
        return attrValue

    def InsertHostInfo(self):
        HostInfo = [(self.AssessDate, self.HostIP, self.Subnet, self.MAC, self.HostName, self.OS, self.OSVersion, 
            self.ConfidenceLevel, self.TotalHigh, self.TotalMedium, self.TotalLow,
            self.TotalInfo, self.TotalOpenPorts, self.TotalFilteredPorts)]

        try:

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
        query = "DROP TABLE IF EXISTS LanguardHosts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `LanguardHosts`(
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
        query = "DROP TABLE IF EXISTS LanguardPorts;"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS `LanguardPorts`(
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
    LanguardParser = LanguardXML(dbName, "./WorkForce/Languard Reports/scanresultxml_Full Scan_164.64.31.1-164.64.31.255_2007_11_30_141240.xml", time.time(), "Languard", [], True)
    InitTables(dbName, True)
    LanguardParser.parse()