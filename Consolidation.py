#-----------------------------------------------------------------------------
# Name:        Consolidation.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/17
# RCS-ID:      $Id: Consolidation.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string, re
import time
from SqliteDatabase import *
import os.path
import math
from Config import *
import Global


def InitTables(DBName, scannerName, dropTable=False):
    db = SqliteDatabase(DBName)
    if not db.OpenConnection():
        return None
    #Hosts table
    
    HostsTable = scannerName + "Hosts"
    PortsTable = scannerName + "Ports"
    
    if dropTable:
        query = "DROP TABLE IF EXISTS " + HostsTable + ";"
        db.ExecuteNonQuery(query)
    
    query = """
        CREATE TABLE IF NOT EXISTS %s(
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
    """%HostsTable
    db.ExecuteNonQuery(query)

    #Ports table
    if dropTable:
        query = "DROP TABLE IF EXISTS " + PortsTable + ";"
        db.ExecuteNonQuery(query)
        
    query = """
        CREATE TABLE IF NOT EXISTS %s(
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
        """%PortsTable
    db.ExecuteNonQuery(query)
    
    db.CloseConnection()

def ConsolidateHosts(DBName, Scanner):
    Hosts = {}
    db = SqliteDatabase(DBName)
    if not db.OpenConnection():
        return

    if 'Nessus' in Global.ConsolidationScanners:
        query = "select AssessDate, IP, MAC, HostName, OS, "
        query += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts from NessusHosts order by IP;"
        rows = db.FetchAllRows(query)
        HostQuery = "insert into " + Scanner + "Hosts" + " (AssessDate, IP, Subnet, MAC, HostName, OS, "
        HostQuery += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        
        for row in rows:
            #Hosts[row[1]] = {}
            AssessDate = row[0]
            #consolidate with nmap
            HostIP = row[1]
            Subnet = HostIP[:HostIP.rfind('.')]
            MAC = []
            if row[2] and row[2] != 'N/A':
                MAC.append(row[2])
            
            HostName = []
            if row[3] and row[3] != 'N/A':
                HostName.append(row[3])
                
            OS = []
            if row[3] and row[3] != 'N/A':
                OS.append(row[4])
                
            OSVersion = []
            if row[5] and row[5] != 'N/A':
                OSVersion.append(row[5])
                
            ConfidenceLevel = row[6]
            High = int(row[7])
            Medium = int(row[8])
            Low = row[9]
            Info = row[10]
            OpenPorts = row[11]
            FilteredPorts = row[12]
        
            if 'Nmap' in Global.ConsolidationScanners:
                HostsTable = "NmapHosts"
                query = "select AssessDate, IP, MAC, HostName, OS, "
                query += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts from %s where IP='%s'"%(HostsTable, HostIP)
                nmapRow = db.FetchOneRow(query)
                if nmapRow:
                    if nmapRow[2] and nmapRow[2] != 'N/A':
                        if len(MAC) > 0:
                            for mac in MAC:
                                if mac.lower() != nmapRow[2].lower():
                                    MAC.append(nmapRow[2])
                                
                        else:
                            MAC.append(nmapRow[2])
                            
                    if nmapRow[4] and nmapRow[4] != 'N/A':
                        if len(OS) > 0:
                            for os in OS:
                                newOs = nmapRow[4].lower()
                                if os.lower().find(newOs) < 0 or os.lower() != newOs:
                                    OS.append(nmapRow[4])
                        else:
                            OS.append(nmapRow[4])
                            
                    if nmapRow[5] and nmapRow[5] != 'N/A':
                        if len(OSVersion) > 0:
                            for os in OSVersion:
                                newOs = nmapRow[5].lower()
                                if os.lower().find(newOs) < 0:
                                    OSVersion.append(nmapRow[5])
                        else:
                            OSVersion.append(nmapRow[5])
                    
                                    
            if 'Retina' in Global.ConsolidationScanners:
                HostsTable = "RetinaHosts"
                query = "select AssessDate, IP, MAC, HostName, OS, "
                query += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts from %s where IP='%s'"%(HostsTable, HostIP)
                lgRow = db.FetchOneRow(query)
                if lgRow:
                    #print 'Nessus High = %d'%High
                    High += int(lgRow[7])
                    #print 'Retina High = %d'%High
                    High = int(math.ceil(High/2.0))
                    #print 'Average High = %d'%High
                    
                    Medium += int(lgRow[8])
                    Medium = int(math.ceil(Medium/2.0))
                    
                    Low += int(lgRow[9])
                    Low = int(math.ceil(Low/2.0))
                    
                    Info += int(lgRow[10])
                    Info = int(math.ceil(Info/2.0))
                    
                    OpenPorts += int(lgRow[11])
                    OpenPorts = int(math.ceil(OpenPorts/2.0))
            
                    FilteredPorts += int(lgRow[12])
                    FilteredPorts = int(math.ceil(FilteredPorts/2.0))

            
            if 'Languard' in Global.ConsolidationScanners:
                HostsTable = "LanguardHosts"
                query = "select AssessDate, IP, MAC, HostName, OS, "
                query += "OSVersion, ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts from %s where IP='%s'"%(HostsTable, HostIP)      
                lgRow = db.FetchOneRow(query)
                if lgRow:
                    #consolidate hostname
                    if lgRow[3] and lgRow[3] != 'N/A':
                        if len(HostName) > 0:
                            for name in HostName:
                                if name.lower() != lgRow[3].lower():
                                    HostName.append(lgRow[3])
                                
                        else:
                            HostName.append(lgRow[3])
                    
                    #consolidate MAC
                    if lgRow[2] and lgRow[2] != 'N/A':
                        if len(MAC) > 0:
                            for mac in MAC:
                                if mac.lower() != lgRow[2].lower():
                                    MAC.append(lgRow[2])
                                
                        else:
                            MAC.append(lgRow[2])
                    
                    newOs = lgRow[4].lower()   
                    if newOs and newOs != 'n/a':
                        if len(OS) > 0:
                            for os in OS:
                                if os.lower().find(newOs) < 0:
                                    OS.append(lgRow[4])
                        else:
                            OS.append(lgRow[4])     
                    
                    #print 'Nessus High = %d'%High
                    High += int(lgRow[7])
                    #print 'Retina High = %d'%High
                    High = int(math.ceil(High/2.0))
                    #print 'Average High = %d'%High
                    
                    Info += int(lgRow[10])
                    Info = int(math.ceil(Info/2.0))
                    
                    OpenPorts += int(lgRow[11])
                    OpenPorts = int(math.ceil(OpenPorts/2.0))
            
                    FilteredPorts += int(lgRow[12])
                    FilteredPorts = int(math.ceil(FilteredPorts/2.0))
            
                           
            HostInfo = [(AssessDate, HostIP, Subnet, string.join(MAC, '; '), string.join(HostName, '; '), 
                string.join(OS, '; '), string.join(OSVersion, '; '), 
                ConfidenceLevel, High, Medium, Low, Info, OpenPorts, FilteredPorts)]

            try:
                db.ExecuteMany(HostQuery, HostInfo)
                
            except Exception, value:
                print str(value)
                
    db.CloseConnection()
    
def ExcludeIPsFromDB():
    if not Config["ExcludeIPs"]:
        return
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        print 'Could not connect to DB in ExcludeIPsFromDB!'
        return
    #First remove all the IP's that are supposed to be excluded from the reports
    if not Config["ExcludeIps"]:
        return
    
    for scanner in Global.ParseScanners:
        tableName = "%sHosts"%scanner
        db.ExecuteNonQuery('delete from %s where IP in %s;'%(tableName, str(Config["ExcludeIPs"])))
        tableName = "%sPorts"%scanner
        db.ExecuteNonQuery('delete from %s where IP in %s;'%(tableName, str(Config["ExcludeIPs"])))
        
    db.CloseConnection()
    
def main():
    #ReadConfigFile()
    print 'Consolidating Reports!'
    try:
        ExcludeIPsFromDB()
    except Exception, ex:
        print 'Excepiton in ExlcudeIPsFromDB ', ex
    
    InitTables(Config["DBName"], Global.ConsolidatedScannerName, True)
    tval = time.strptime(Config["AssessmentDate"], "%m/%d/%Y")
    assessDate = time.mktime(tval)
    ConsolidateHosts(Config["DBName"], Global.ConsolidatedScannerName)
    print 'Done Consolidating Reports!'
    
    
if __name__ == "__main__":
    pass
    """
    ReadConfigFile()
    main()
    """