## returns a DOM corresponding to the specified xml file

import sys, string, os, re
from xml.dom import minidom, Node
import MySQLdb
import time
from stat import *
import sys, string, os, re
#import MySQLdb
from time import mktime
from datetime import datetime
import datetime
import time
from pylab import *

from SqliteDatabase import *


class SaraXML:
    def __init__(self, reportPath, dbFile):
        self.xmlDOM = minidom.parse(reportPath)
        self.dbFile = dbFile
    
    def parse(self, parent, assessDate):
    #def SARA(self, parent, outFile, db_connect, unix_date,asci_date):
        '''
        bug -- missing some data ... particularly that of ips with no vulns... fix me
        '''
        db_connect = self.make_db_connection()
        source = "SARA"
        hostname = ""
        ip = ""
        verity = ""
        firewall = ""
        cve = "NULL"
        port = ""
        servicename = ""
        for host in parent.getElementsByTagName("HOST"):
            hostname = "NULL"
            ip = "NULL"
            verity = "NULL"
            firewall = "NULL"
            cve = "NULL"
            port = "NULL"
            servicename = "NULL"
            ip = self.getContent(host.getElementsByTagName("HOST_IP_ADDRESS")[0])
            mac = self.getContent(host.getElementsByTagName("HOST_MAC_ADDRESS")[0])
            firewall= self.getContent(host.getElementsByTagName("HOST_FIREWALL")[0])
            for Host_Desc in host.getElementsByTagName("HOST_DESCRIPTION"):
                hostname = self.getContent(Host_Desc.getElementsByTagName("HOST_NAME")[0])
                #print "HOSTNAME1",self.getContent(Host_Desc.getElementsByTagName("HOST_GREEN_SVC")[0])
                #print "HOSTNAME2",self.getContent(Host_Desc.getElementsByTagName("HOST_RED_VULNERABILITIES")[0])
                #print "HOSTNAME3",self.getContent(Host_Desc.getElementsByTagName("HOST_YELLOW_VULNERABILITIES")[0])
                #print "HOSTNAME4",self.getContent(Host_Desc.getElementsByTagName("HOST_BROWN_VULNERABILITIES")[0])
                #print "HOSTNAME5",self.getContent(Host_Desc.getElementsByTagName("HOST_GRAY_VULNERABILITIES")[0])
            for vunls in host.getElementsByTagName("VULNERABILITIES"):
                for vun in vunls.getElementsByTagName("VULNERABILITY"):					
                    verity = self.getContent(vunls.getElementsByTagName("SEVERITY")[0]).strip()
                    for service in vun.getElementsByTagName("SERVICE"):
                        servicename = self.getContent(service.getElementsByTagName("NAME")[0])
                        port = self.getContent(service.getElementsByTagName("PORT")[0])
                    if vun.getElementsByTagName("CLASS"):
                        #print "CLASSSSS ",self.getContent(vunls.getElementsByTagName("CLASS")[0])
                        #print "DATAAAAA ",self.getContent(vunls.getElementsByTagName("DATA")[0])
                        for NDV in vunls.getElementsByTagName("NVD"):
                            cve = self.getContent(NDV.getElementsByTagName("CVE")[0])
                            #print "NVD_CVSS",self.getContent(NDV.getElementsByTagName("NVD_CVSS")[0])
                            #print "NVD_SEVERITY",self.getContent(NDV.getElementsByTagName("NVD_SEVERITY")[0])
                            #print "NVD_RANGE",self.getContent(NDV.getElementsByTagName("NVD_RANGE")[0])
                            #print "NVD_VULN_TYPES",self.getContent(NDV.getElementsByTagName("NVD_VULN_TYPES")[0])
                            #print "NVD_LOSS_TYPES",self.getContent(NDV.getElementsByTagName("NVD_LOSS_TYPES")[0])
                            #print "NVD_DESC",self.getContent(NDV.getElementsByTagName("NVD_DESC")[0])
                            #missing NVD_REF,SANS, False Postives
                    ip = ip.strip()
                    sql = "Insert INTO metasploit_table (ip, mac, service, port, serv, CVE, source, unix_date, ascii_date) Values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" %(ip, mac, servicename, port, verity, cve, source, unix_date, asci_date)
                    db_connect.execute(sql)
                    #print "%s|%s|%s|%s|%s|%s|%s|%s" % (ip,mac,firewall,hostname,servicename,port,verity,cve) 
        db_connect.close()


if __name__ == "__main__":
    dbName = "Test.db"
    saraParser = SaraXML("./SaraReports/somesara.xml", "Test.db")
    
    root = saraParser.xmlDOM
    saraParser.parse(root, time.time())