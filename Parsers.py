#-----------------------------------------------------------------------------
# Name:        Parsers.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/17
# Modified:    10/1/2009
# RCS-ID:      $Id: Parsers.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string, re, shutil, os
import xml.sax.handler
import time
import pylab
from SqliteDatabase import *
import xml.sax
import os.path
from NessusXML import *
from LanguardXML import *
from RetinaHTML import *
from NmapXML import *
from Config import *
import Global

def InitTables(db, scannerName, dropTable=False):
    """
    db = SqliteDatabase(DBName)
    if not db.OpenConnection():
        return None
    #Hosts table
    """
    
    hostsTable = scannerName + "Hosts"
    portsTable = scannerName + "Ports"
    if dropTable:
        query = "DROP TABLE IF EXISTS " + hostsTable + ";"
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
    """%hostsTable
    db.ExecuteNonQuery(query)

    #Ports table
    if dropTable:
        query = "DROP TABLE IF EXISTS " + portsTable + ";"
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
        """%portsTable
    db.ExecuteNonQuery(query)
    #db.CloseConnection()
    
def CreateNavigationTable(db):
    """
    db = SqliteDatabase(DBName)
    if not db.OpenConnection():
        return None
    """
    query = "DROP TABLE IF EXISTS Navigation;"
    db.ExecuteNonQuery(query)
    
    query = """
        CREATE TABLE Navigation(
        `GrandParent` varchar(200),
        `Parent` varchar(200),
        `ReportGroup` varchar(200),
        `LinkText` varchar(200),
        `Link` varchar(300)
        );
    """
    db.ExecuteNonQuery(query)


def ParseNessusReports(db, reportPath, assessDate, excludeIPs, checkDuplicateIPs, dropTable):
    scannerName = "Nessus"
    InitTables(db, scannerName, dropTable)
    """
    db = SqliteDatabase(self.DBName)
    if not db.OpenConnection():
        return
    """
    for root, dirs, files in os.walk(reportPath):
        for name in files:
            try:
                filePath = os.path.join(root, name)
                extension = filePath[filePath.rfind('.'):]
                if extension.find("xml") >= 0:
                    #print 'parsing ', filePath
                    try:
                        parser = NessusXML(db, filePath, assessDate, scannerName, excludeIPs, checkDuplicateIPs)
                        parser.parse()
                        parser = None
                    except Exception, value:
                        print 'Exception in file: %s : value: %s'%(filePath,str(value))
                        parser = None
                        continue
            except Exception, value:
                print 'Exception in Nessus Parsing: ', str(value)
                continue
    #db.CloseConnection()
    
     
def ParseLanguardReports(db, reportPath, assessDate, excludeIPs, checkDuplicateIPs, dropTable):
    scannerName = "Languard"
    """
    db = SqliteDatabase(self.DBName)
    if not db.OpenConnection():
        return
    """
    InitTables(db, scannerName, dropTable)
    for root, dirs, files in os.walk(reportPath):
        for name in files:
            try:
                filePath = os.path.join(root, name)
                extension = filePath[filePath.rfind('.'):]
                if extension.find("xml") >= 0:
                    #print 'parsing ', filePath
                    try:
                        parser = LanguardXML(db, filePath, assessDate, scannerName, excludeIPs, checkDuplicateIPs)
                        parser.parse()
                        parser = None
                    except Exception, value:
                        print 'Exception in file: %s : value: %s'%(filePath,str(value))
                        parser = None
                        continue
            except Exception, value:
                print 'Exception in Languard Parsing: ', str(value)
                continue
    #db.CloseConnection()
            
def ParseNmapReports(db, reportPath, assessDate, excludeIPs, checkDuplicateIPs, dropTable):
    scannerName = "Nmap"
    """
    db = SqliteDatabase(self.DBName)
    if not db.OpenConnection():
        return
    """
    InitTables(db, scannerName, dropTable)
    for root, dirs, files in os.walk(reportPath):
        for name in files:
            try:
                filePath = os.path.join(root, name)
                extension = filePath[filePath.rfind('.'):]
                if extension.find("xml") >= 0:
                    #print 'parsing ', filePath
                    try:
                        parser = NmapXML(db, filePath, assessDate, scannerName, excludeIPs, checkDuplicateIPs)
                        parser.parse()
                        parser = None
                    except Exception, value:
                        print 'Exception in file: %s : value: %s'%(filePath,str(value))
                        parser = None
                        continue
            except Exception, value:
                print 'Exception in Nmap Parsing: ', str(value)
                continue
    #db.CloseConnection()
                
def ParseRetinaReports(db, reportPath, assessDate, excludeIPs, checkDuplicateIPs, dropTable):
    scannerName = "Retina"
    
    InitTables(db, scannerName, dropTable)
    
    for root, dirs, files in os.walk(reportPath):
        for name in files:
            try:
                filePath = os.path.join(root, name)
                extension = filePath[filePath.rfind('.'):]
                
                if extension.find("html") >= 0:
                    #print 'parsing ', filePath
                    try:
                        parser = RetinaHTML(db, filePath, assessDate, scannerName, excludeIPs, checkDuplicateIPs)
                        parser.parse()
                        parser = None
                    except Exception, value:
                        print 'Exception in file: %s : value: %s'%(filePath,str(value))
                        parser = None
                        continue
            except Exception, value:
                print 'Exception in Retina Parsing: ', str(value)
                continue
    #db.CloseConnection() 

def main():
    
    tval = time.strptime(Config["AssessmentDate"], "%m/%d/%Y")
    assessDate = time.mktime(tval)
    
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return

    CreateNavigationTable(db)
    
    assetsFolder = 'assets'
    destFolder = os.path.join(Config["OutputPath"], assetsFolder)
    #destFolder = os.path.join(Config["OutputPath"], assetsFolder)
    if not os.path.exists(destFolder):
        os.makedirs(destFolder)
        for afile in os.listdir(assetsFolder):
            if (afile.find('.txt') == -1):
                shutil.copyfile(os.path.join(assetsFolder, afile), os.path.join(destFolder, afile))
    
    pylab.__InitPylab__()
    
    
    dropTable = True
    
    if 'Nessus' in Global.ParseScanners:
        print 'Parsing Nessus reports...'
        ParseNessusReports(db, Config["NessusReportPath"], assessDate, Config["ExcludeIPs"], Global.CheckDuplicateIPs, dropTable)
        print 'Done parsing Nessus reports!'

    if 'Nmap' in Global.ParseScanners:
        print 'Parsing Nmap reports...'
        ParseNmapReports(db, Config["NmapReportPath"], assessDate, Config["ExcludeIPs"], Global.CheckDuplicateIPs, dropTable)
        print 'Done parsing Nmap reports!'
    
    if 'Retina' in Global.ParseScanners:
        print 'Parsing Retina reports...'
        ParseRetinaReports(db, Config["RetinaReportPath"], assessDate, Config["ExcludeIPs"], Global.CheckDuplicateIPs, dropTable)
        print 'Done parsing Retina reports!'
    
    if 'Languard' in Global.ParseScanners:
        print 'Parsing Languard reports...'
        ParseLanguardReports(db, Config["LanguardReportPath"], assessDate, Config["ExcludeIPs"], Global.CheckDuplicateIPs, dropTable)
        print 'Done parsing Languard reports!'
        
    db.CloseConnection()
    
    print 'Done parsing all reports!'
    


if __name__ == "__main__":
    ReadConfigFile()
    main()