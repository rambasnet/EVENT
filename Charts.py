#-----------------------------------------------------------------------------
# Name:        Charts.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2008/01/19
# Modified:    10/1/2009
# RCS-ID:      $Id: Charts.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import string, re
import time
from SqliteDatabase import *
import os.path
import math, sys
from pylab import *
import pylab

import gc,getopt
from Config import *
import Global

SubnetHostsSet = set()

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

def PieSeverityPercentage(Scanner, subnet=""):
    """Creates a pie chart based on high, medium, low percentage"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    hostsTable = Scanner + "Hosts"
    global navigationQuery
    
    if subnet:
        query = "select count(*), sum(High), sum(Medium), sum(Low) from %s where (Subnet='%s');"%(hostsTable, (subnet))
    else:
        query = "select count(*), sum(High), sum(Medium), sum(Low) from %s;"%hostsTable
        
    row = db.FetchOneRow(query)
    if row:
        total = 1
        high = 0
        medium = 0
        low = 0
        if row[0]:
            total = float(row[0])
        if row[1]:
            high = int(row[1])
        if row[2]:
            medium = int(row[2])
        if row[3]:
            low = int(row[3])
            
        perHigh = '%.2f'%((high/total)*100)
        perMedium = '%.2f'%((medium/total)*100)
        perLow = '%.2f'%((low/total)*100)
        
        labels = 'High', 'Medium', 'Low'
        Vulns = [perHigh, perMedium, perLow]
        figure(1, figsize=(8,8))
        explode=(0.05, 0, 0)
        pie(Vulns, explode=explode, labels=labels, colors=('red', 'orange', 'yellow'), autopct='%1.2f%%', shadow=True)
        htmlFile = '%sPieSeverityPercentage.png'%Scanner
        if subnet:
            title('%s - Percentage of Vulnerabilities by Risk Level in Subnet %s'%(Scanner, subnet))
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fileName = os.path.join(dirPath, '%sPieSeverityPercentage'%Scanner)
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Charts"%Scanner, "Vulnerabilites Percent by Risk Level", "./%s/%s"%(subnet, htmlFile)),]) 
        else:
            title('%s - Network-wide Percentage of Vulnerabilities by Risk Level'%Scanner)
            fileName = os.path.join(Config["OutputPath"], '%sPieSeverityPercentage'%Scanner)
            db.ExecuteMany(navigationQuery, [('Network', '', "%s Charts"%Scanner, "Vulnerabilites Percent by Risk Level", "./%s"%(htmlFile)),]) 
            
        draw()
        savefig(fileName)
        close()
    db.CloseConnection()

        
def BarSeverityCount(Scanner, subnet=""):
    """Creates a pie chart based on high, medium, low percentage"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    global navigationQuery
    hostsTable = Scanner + "Hosts"
    if subnet:
        query = "select count(*), sum(High), sum(Medium), sum(Low) from %s where Subnet='%s';"%(hostsTable, subnet)
    else:
        query = "select count(*), sum(High), sum(Medium), sum(Low) from %s;"%hostsTable
        
    row = db.FetchOneRow(query)
    if row:
        total = 1
        high = 0
        medium = 0
        low = 0
        if row[0]:
            total = float(row[0])
        if row[1]:
            high = int(row[1])
        if row[2]:
            medium = int(row[2])
        if row[3]:
            low = int(row[3])
        
        N = 3
        Vulns = (high, medium, low)
        ind = arange(N)  # the x locations for the groups
        width = 0.35       # the width of the bars
        p1 = bar(ind, Vulns, width, color=('red', 'orange', 'yellow'))
        
        ylabel('Vulnerability Count')
        htmlFile = '%sBarSeverityCount.png'%Scanner
        if subnet:
            title('%s - Vulnerability Count by Risk Level in Subnet %s'%(Scanner, subnet))
            dirPath = os.path.join(Config["OutputPath"], subnet)
            fileName = os.path.join(dirPath, '%sBarSeverityCount'%Scanner)
            db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Charts"%Scanner, "Vulnerability Count by Risk Level", "./%s/%s"%(subnet, htmlFile)),]) 
        else:
            title('%s - Network-wide Vulnerability Count by Risk Level'%Scanner)
            fileName = os.path.join(Config["OutputPath"], '%sBarSeverityCount'%Scanner)
            db.ExecuteMany(navigationQuery, [('Network', '', "%s Charts"%Scanner, "Vulnerability Count by Risk Level", "./%s"%(htmlFile)),]) 
            
        xticks(ind+(width/2), ('High (%s)'%high, 'Medium (%s)'%medium, 'Low (%s)'%low) )
        xlabel('Risk Level')
        xlim(-width,len(ind))
        draw()
        savefig(fileName)
        #show()
        close()
    db.CloseConnection()
    
def BarTop5MostVulnerableHosts(Scanner, subnet=""):
    """Creates a pie chart based on high, medium, low percentage"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    global navigationQuery
    hostsTable = Scanner + "Hosts"
    if subnet:
        query = "select IP, High, Medium, Low from %s where (Subnet='%s') order by High desc, Medium desc, Low desc limit 5;"%(hostsTable, subnet)
        #print query
    else:
        query = "select IP, High, Medium, Low from %s order by High desc, Medium desc, Low desc limit 5;"%(hostsTable)
    rows = db.FetchAllRows(query)
    
    if not rows:
        db.CloseConnection()
        return
    
    IPs = []
    high = []
    medium = []
    low = []
    for row in rows:
        IPs.append(row[0])
        high.append(int(row[1]))
        medium.append(int(row[2]))
        low.append(int(row[3]))
    

    N = len(rows)
    hVuln = high
    mVuln = medium
    lVuln = low
    
    ind = arange(N)     # the x locations for the groups
    width = 0.25       # the width of the bars
    p1 = bar(ind, hVuln, width, color='red')
    p2 = bar(ind+width, mVuln, width, color='orange')
    p3 = bar(ind+width+width, lVuln, width, color='yellow')
    
    ylabel('Vulnerability Count')
    htmlFile = '%sBarTop5MostVulnerableHosts.png'%Scanner
    if subnet:
        title('%s - Top 5 Most Vulnerable Hosts in Subnet %s'%(Scanner, subnet))
        dirPath = os.path.join(Config["OutputPath"], subnet)
        fileName = os.path.join(dirPath, '%sBarTop5MostVulnerableHosts'%Scanner)
        db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Charts"%Scanner, "Top 5 Most Vulnerable Hosts", "./%s/%s"%(subnet, htmlFile)),]) 
    else:
        title('%s - Network-wide Top 5 Most Vulnerable Hosts'%(Scanner))
        fileName = os.path.join(Config["OutputPath"], '%sBarTop5MostVulnerableHosts'%Scanner)
        db.ExecuteMany(navigationQuery, [('Network', '', "%s Charts"%Scanner, "Top 5 Most Vulnerable Hosts", "./%s"%(htmlFile)),]) 
    
    xticks(ind+(3*width/2), IPs )
    labels = getp(gca(), 'xticklabels')
    setp(labels, fontsize=10)
    
    xlabel('Host')
    
    xlim(-width,len(ind))
    

    if not p1:
        p1 = ['']
    if not p2:
        p2 = ['']
    if not p3:
        p3 = ['']
    
    
    legend( (p1[0], p2[0], p3[0]), ('High', 'Medium', 'Low'), shadow=True)
    draw()
    savefig(fileName)
    close()
    db.CloseConnection()
        
    
    
def BarTop5MostVulnerableSubnets(ScannerName):
    """Creates a bar chart based on high, medium, low vulnerability count for subnets"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    hostsTable = ScannerName + "Hosts"

    query = "select Subnet, sum(High) as totalHigh, sum(Medium) as totalMedium, sum(Low) as totalLow from %s group by Subnet order by totalHigh desc, totalMedium desc, totalLow desc limit 5;"%(hostsTable)
        
    rows = db.FetchAllRows(query)
    if not rows:
        db.CloseConnection()
        return
    
    global navigationQuery
    
    Subnets = []
    high = []
    medium = []
    low = []
    for row in rows:
        Subnets.append(row[0])
        high.append(int(row[1]))
        medium.append(int(row[2]))
        low.append(int(row[3]))
    
    #if len(rows) == 5:
    N = len(rows)
    hVuln = high
    mVuln = medium
    lVuln = low
    
    ind = arange(N)     # the x locations for the groups
    width = 0.25       # the width of the bars
    p1 = bar(ind, hVuln, width, color='red')
    p2 = bar(ind+width, mVuln, width, color='orange')
    p3 = bar(ind+width+width, lVuln, width, color='yellow')
    
    ylabel('Vulnerability Count')
    
    htmlFile = '%sBarTop5MostVulnerableSubnets.png'%ScannerName
    title('%s - Top 5 Most Vulnerable Subnets'%(ScannerName))
    fileName = os.path.join(Config["OutputPath"], '%sBarTop5MostVulnerableSubnets'%ScannerName)
    db.ExecuteMany(navigationQuery, [('Network', '', "%s Charts"%ScannerName, "Bar Top 5 Vulnerable Subnets", "./%s"%(htmlFile)),]) 
    xticks(ind+(3*width/2), Subnets )
    labels = getp(gca(), 'xticklabels')
    setp(labels, fontsize=10)
    
    xlabel('Host')
    
    xlim(-width,len(ind))
    
    if not p1:
        p1 = ['']
    if not p2:
        p2 = ['']
    if not p3:
        p3 = ['']
        
    legend( (p1[0], p2[0], p3[0]), ('High', 'Medium', 'Low'), shadow=True)
    draw()
    savefig(fileName)
    close()
    db.CloseConnection()
        
        
def BarTop5CommonVulnerablePorts(Scanner, severity, subnet=""):
    """"""
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    global navigationQuery
    portsTable = "%sPorts"%Scanner
    level = "High"
    barColor = "red"
    if severity == 2:
        level = "Medium"
        barColor = "orange"
    elif severity == 1:
        level = "Low"
        barColor = "yellow"
    
    if subnet:
        query = "select count(Port) as Frequency, Port, Service from %s where (severity = %s and port<>100000 and IP like '%s') group by Port having Service <> 'N/A' order by Frequency desc limit 5;"%(portsTable, str(severity), (subnet+"%"))
    else:
        query = "select count(Port) as Frequency, Port, Service from %s where severity = %s and port<>100000 group by Port having Service <> 'N/A' order by Frequency desc limit 5;"%(portsTable, str(severity))
   
    rows = db.FetchAllRows(query)
    if not rows:
        db.CloseConnection()
        return
    
    Labels = []
    Frequency = []
    
    for row in rows:
        Frequency.append(int(row[0]))
        label = str(row[1]) + ":" + str(row[2])[:10]
        Labels.append(label)
        
    #if len(rows) == 5:
    N = len(rows)
    ind = arange(N)     # the x locations for the groups
    width = 0.25       # the width of the bars
    p1 = bar(ind, Frequency, width, color=barColor)
    
    
    ylabel('%s Vulnerability Count'%level)
    htmlFile = '%sBarTop5%sCommonVulnerablePorts.png'%(Scanner, level)
    if subnet:
        title('%s - Top 5 Ports with %s Vulnerabilities in Subnet %s'%(Scanner, level, subnet))
        dirPath = os.path.join(Config["OutputPath"], subnet)
        fileName = os.path.join(dirPath, '%sBarTop5%sCommonVulnerablePorts'%(Scanner, level))
        db.ExecuteMany(navigationQuery, [('Subnet', subnet, "%s Charts"%Scanner, "Top 5 Ports - %s Vulnerabilities"%level, "./%s/%s"%(subnet, htmlFile)),]) 
    else:
        title('%s - Network-wide Top 5 Ports with %s Vulnerabilities'%(Scanner, level))
        fileName = os.path.join(Config["OutputPath"], '%sBarTop5%sCommonVulnerablePorts'%(Scanner, level))
        db.ExecuteMany(navigationQuery, [('Network', '', "%s Charts"%Scanner, "Top 5 Ports - %s Vulnerabilities"%level, "./%s"%(htmlFile)),]) 
        
    #legend( (p1[0], p2[0], p3[0]), ('High', 'Medium', 'Low'), shadow=False)
    font = {'fontname'   : 'Courier',
           'fontweight' : 'normal',
           'fontsize'   : 8}
    xticks(ind+(width/2), Labels)
    labels = getp(gca(), 'xticklabels')
    setp(labels, fontsize=10)
    #rc('xtick', font)
    #ticks.set_fontsize(8)
    #ticks.set_fontweight('normal')
    xlabel('Port & Service')
    xlim(-width,len(ind))
    draw()
    savefig(fileName)
    
    #show()
    close()
        
    db.CloseConnection()
    
    
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
            
            #subnet = row[0][:row[0].rfind('.')]
            
            #if SubnetHostsSet.has_key(scanner):
            SubnetHostsSet.add(row[0].strip())
            #else:
            #    SubnetHostsSet[scanner] = set([subnet])
            
    db.CloseConnection()
      
      
def RunReport1(scanner, severityLevel):
    if scanner in Global.ConsolidationScanners:
        print 'Creating Subnet-wise Charts: # 1 for Scanner %s SeverityLevel %d '%(scanner, severityLevel)
        for subnet in SubnetHostsSet:
            dirPath = os.path.join(Config["OutputPath"], subnet)
            if not os.path.exists(dirPath):
                os.makedirs(dirPath)

            #for severity in Config["SeverityLevels:
            BarTop5CommonVulnerablePorts(scanner, severityLevel, subnet)
                
        print 'Done Creating Subnet-wise Charts: # 1'
    else:
        print 'Error: Scanner %s not in ConsolidationScanners list in Config["py file'%scanner
            
            
def RunSubnetBarSeverityCount():
    print 'Creating Subnet-wise BarSeverityCount Charts!'
    for subnet in SubnetHostsSet:
        dirPath = os.path.join(Config["OutputPath"], subnet)
        if not os.path.exists(dirPath):
            os.makedirs(dirPath)
            
        try:
            BarSeverityCount(Global.ConsolidatedScannerName, subnet)
        except Exception, value:
            print 'Exception in RunSubnetBarSeverityCount subnet %s value: %s'%(subnet, value)
            
        
    print 'Done Creating Subnet-wise BarSeverityCount Charts!'
    
    
    
def RunSubnetPieSeverityPercentage():
    print 'Creating Subnet-wise PieSeverityPercentage Charts!'
    for subnet in SubnetHostsSet:
        dirPath = os.path.join(Config["OutputPath"], subnet)
        if not os.path.exists(dirPath):
            os.makedirs(dirPath)
            
        try:
            PieSeverityPercentage(Global.ConsolidatedScannerName, subnet)
        except Exception, value:
            print 'Exception in RunSubnetPieSeverityPercentage subnet %s value: %s'%(subnet, value)
            
        
    print 'Done Creating Subnet-wise PieSeverityPercentage Charts!'
        
        
def RunSubnetBarTop5MostVulnerableHosts():
    print 'Creating Subnet-wise BarTop5MostVulnerableHosts Charts!'
    for subnet in SubnetHostsSet:
        dirPath = os.path.join(Config["OutputPath"], subnet)
        if not os.path.exists(dirPath):
            os.makedirs(dirPath)
            
        try:
            BarTop5MostVulnerableHosts(Global.ConsolidatedScannerName, subnet)
        except Exception, value:
            print 'Exception in RunSubnetBarTop5MostVulnerableHosts subnet %s value: %s'%(subnet, value)
            
    print 'Done Creating Subnet-wise BarTop5MostVulnerableHosts Charts!'
    
def RunReportSubnetsRest(chartType):
    #gc.enable()
    print 'Creating Subnet-wise Charts: # %d!'%chartType
    for subnet in SubnetHostsSet:
        dirPath = os.path.join(Config["OutputPath"], subnet)
        if not os.path.exists(dirPath):
            os.makedirs(dirPath)
            
        for scanner in Global.ConsolidationScanners:
            try:
                if chartType == 3:
                    BarSeverityCount(scanner, subnet)
                elif chartType == 4:
                    BarTop5MostVulnerableHosts(scanner, subnet)
                elif chartType == 5:
                    PieSeverityPercentage(scanner, subnet)
            except Exception, value:
                print 'Exception in RunReportSubnetRest: value::', value
                
    #gc.collect()
    print 'Done Creating Subnet-wise Charts: # %d!'%chartType
    
def RunReport0():
    print 'Creating Network-wide Charts!'
    PieSeverityPercentage(Global.ConsolidatedScannerName)
    BarSeverityCount(Global.ConsolidatedScannerName)
    BarTop5MostVulnerableHosts(Global.ConsolidatedScannerName)
    BarTop5MostVulnerableSubnets(Global.ConsolidatedScannerName)
    
    for scanner in Global.ConsolidationScanners:
        for severity in Global.SeverityLevels:
            BarTop5CommonVulnerablePorts(scanner, severity)
    
        PieSeverityPercentage(scanner)
        BarSeverityCount(scanner)
        BarTop5MostVulnerableHosts(scanner)
        BarTop5MostVulnerableSubnets(scanner)
        
    print 'Done Creating Network-wide Charts!'
    
    
def Usage():
    print 'Usage:'
    print 'Charts.pyc -r [chartType] -p [parserName] -s [severityLevel]'
    print 'Where charType can be any number 0-5'
    print 'parseName can be one of: Nessus, Retina, Languard, Consolidated'
    print 'severityLevel can be any number from 1-3'


def main():
    #ReadConfigFile()
    tval = time.strptime(Config["AssessmentDate"], "%m/%d/%Y")
    assessDate = time.mktime(tval)
    
    pylab.__InitPylab__()
        
    if not os.path.isdir(Config["OutputPath"]):
        os.mkdir(Config["OutputPath"])
    
    GetHostsSubnets()
    RunReport0()
    for i in range(3):
        for parser in Global.ConsolidationScanners:
            RunReport1(parser, i+1)
        
    RunReportSubnetsRest(3)
    RunReportSubnetsRest(4)
    RunReportSubnetsRest(5)
    RunSubnetPieSeverityPercentage()
    RunSubnetBarSeverityCount()
    RunSubnetBarTop5MostVulnerableHosts()


if __name__ == "__main__":
    pass
    """
    ReadConfigFile()
    
    argv = sys.argv[1:]
    try:
        tval = time.strptime(Config["AssessmentDate"], "%m/%d/%Y")
        assessDate = time.mktime(tval)
            
        pylab.__InitPylab__()
            
        if not os.path.isdir(Config["OutputPath"]):
            os.mkdir(Config["OutputPath"])
        
        opts, args = getopt.getopt(argv, "hr:p:s:", ["help", "chartType", "parserName", "severityLevel"])
        #print opts, args
        
        for opt, arg in opts:
            
            if opt in ('-h', '--help'):
                Usage()
                sys.exit()
            elif opt in ('-r', '--chartType'):
                chartType = arg

            elif opt in ('-p', '--parserName'):
                parserName = arg
                            
            elif opt in ('-s', '--severityLevel'):
                severityLevel = int(arg)
                
        if int(chartType) == 0:
            RunReport0()
        elif int(chartType) == 1:
            GetHostsSubnets()
            RunReport1(parserName, severityLevel)
            
        elif int(chartType) in [3,4,5]:
            GetHostsSubnets()
            RunReportSubnetsRest(int(chartType))
        
        elif int(chartType) == 6:
            GetHostsSubnets()
            RunSubnetPieSeverityPercentage()
            
        elif int(chartType) == 7:
            GetHostsSubnets()
            RunSubnetBarSeverityCount()
            
        elif int(chartType) == 8:
            GetHostsSubnets()
            RunSubnetBarTop5MostVulnerableHosts()
            
        else:
            Usage()
            sys.exit(1)
    
    except:
        #Usage()
        main()
        #sys.exit(2)
        
    """
    
    
    
