#-----------------------------------------------------------------------------
# Name:        Navigation.py
# Purpose:     
#
# Author:      Ram B. Basnet
#
# Created:     2009/10/01
# RCS-ID:      $Id: Navigation.py $
# Copyright:   (c) 2009
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------


import string, re
import time, shutil
from SqliteDatabase import *
import os.path
from Config import *

def GenerateNavigation():
    #ReadConfigFile()
    print 'Generating Report Browser...'
    db = SqliteDatabase(Config["DBName"])
    if not db.OpenConnection():
        return
    
    destPath = os.path.join(Config["OutputPath"], 'assets')
    try:
        os.mkdir(destPath)
    except:
        pass
    
    for afile in os.listdir('assets'):
        srcFile = os.path.join('assets', afile)
        destFile = os.path.join(destPath, afile)
        shutil.copy(srcFile, destFile)
        
    fileName = os.path.join(Config["OutputPath"], 'ReportBrowser.html')
    
    fout = open(fileName, 'w')
    fout.write("""
            <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
            <html>\n
            <head>\n
            </head>\n
            <frameset cols="20%,80%">\n
            <frame src="Navigator.html" scrolling="yes" id="navigationFrame" title="Navigation" />\n
            <frame src="" name="contentFrame" scrolling="yes" id="contentFrame" title="Content Frame" />\n
            </frameset>\n
            </html>
            """)
    fout.close()
    
    fileName = os.path.join(Config["OutputPath"], 'Navigator.html')
    fout = open(fileName, 'w')
    fout.write("""<HTML>\n
        <head>\n
        <link rel="stylesheet" href="assets/styles.css" />\n
        <script type="text/javascript" src="assets/jquery.min.js"></script>\n
        <script type="text/javascript" src="assets/animatedcollapse.js">\n
        
        /***********************************************\n
        * Animated Collapsible DIV v2.4- (c) Dynamic Drive DHTML code library (www.dynamicdrive.com)\n
        * This notice MUST stay intact for legal use\n
        * Visit Dynamic Drive at http://www.dynamicdrive.com/ for this script and 100s more\n
        ***********************************************/\n
        </script>

        <script type="text/javascript">\n
        """)
        
    query = "select ReportGroup from Navigation where GrandParent='Network' group by ReportGroup order by ReportGroup;"
    networkReportGroups = db.FetchAllRows(query)
    
    query = "select distinct(Parent) from Navigation where GrandParent='Subnet' order by Parent;"
    subnets = db.FetchAllRows(query)
    
    query = "select distinct(Parent) from Navigation where GrandParent='Individual' order by Parent;"
    individuals = db.FetchAllRows(query)
    
    
    for i in range(len(networkReportGroups)):
        divName = 'Network%d'%(i+1)
        fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName)
        divName += "Report"
        fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName)
        
    i = 1
    subnetDict = {}
    for row in subnets:
        divName = 'Subnet%d'%(i)
        fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName)
        query = "select ReportGroup from Navigation where GrandParent='Subnet' and Parent='%s' group by ReportGroup order by ReportGroup;"%(row[0])
        rows = db.FetchAllRows(query)
        subnetDict[row[0]] = rows
        for j in range(len(rows)):
            divName1 = "%sGroup%d"%(divName, j+1)
            fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName1)
            divName1 += "Report"
            fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName1)
             
        i += 1
    
    i = 1
    #subnetDict = {}
    for row in individuals:
        divName = 'Individual%d'%(i)
        fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName)
        divName += "Report"
        fout.write("animatedcollapse.addDiv('%s', 'fade=1;')\n"%divName)
        i += 1
        
    fout.write(
        """
        animatedcollapse.ontoggle=function($, divobj, state){ //fires each time a DIV is expanded/contracted
        //$: Access to jQuery
        //divobj: DOM reference to DIV being expanded/ collapsed. Use "divobj.id" to get its ID
        //state: "block" or "none", depending on state
        }
        animatedcollapse.init()\n
        
        function toggleBars(name, count)
        {
            var i;
            for (i=1; i<=count; i = i+1)
            {
                var id = name+i;
                animatedcollapse.toggle(id);
            }
        }
        </script>\n
        </head>\n
        <body>\n

        <p></p>
        """)
    fout.write("""
        <a href="javascript:toggleBars('Network', %d)" class="toggleBar">Network-wide Reports</a>
        """%len(networkReportGroups))
    
    """
        CREATE TABLE IF NOT EXISTS Navigation(
        `GrandParent` varchar(200),
        `Parent` varchar(200),
        `ReportGroup` varchar(200),
        `LinkText` varchar(200),
        `Link` varchar(300)
    """
    for i in range(len(networkReportGroups)):
        divID = 'Network%d'%(i+1)
        reportDiv = "%sReport"%(divID)
        #<a href="#" rel="toggle[ConsolidatedReports]" data-openimage="assets/arrowup.jpg" data-closedimage="assets/arrowdown.jpg" class="toggleBar">Consolidated Reports <img src="assets/arrowdown.jpg" width="16px" height="16px;" /> </a>
        fout.write("""
            <div id="%s" class="toggleBar1">\n
                <a href="#" rel="toggle[%s]" data-openimage="assets/arrowup.jpg" data-closedimage="assets/arrowdown.jpg" style="text-decoration:none;">%s <img src="assets/arrowdown.jpg"/></a><br />
            </div>"""%(divID, reportDiv, networkReportGroups[i][0]))
        fout.write("""
            <div id="%s" class="tb1reports">
                """%(reportDiv))
        query = "select Link, LinkText from Navigation where GrandParent='Network' and ReportGroup='%s' order by LinkText"%(networkReportGroups[i][0])
        rows = db.FetchAllRows(query)
        for row in rows:
            fout.write("""
                <a href="%s" style="text-decoration:none;" target="contentFrame">%s</a><br />
                """%(row[0], row[1]))
        
        fout.write("</div>\n")
        
    fout.write("<p></p><p></p>\n")
    
    #now write subnet navigation
    fout.write("""
        <a href="javascript:toggleBars('Subnet', %d)" class="toggleBar">Subnet-wide Reports</a>
        """%len(subnetDict))
        
    i = 1
    for key in subnetDict:
        subnetID = 'Subnet%d'%(i)
        
        fout.write("""
            <div id="%s" class="toggleBar1">\n
                <a href="javascript:toggleBars('%sGroup', %d)" style="text-decoration:none;">%s</a><br />
            </div>"""%(subnetID, subnetID, len(subnetDict[key]), key))
          
        j = 1  
        for row in subnetDict[key]:
            groupDiv = "%sGroup%d"%(subnetID, j)
            reportDiv = "%sReport"%groupDiv
            fout.write("""
                    <div id="%s" class="toggleBar2">
                    <a href="#" rel="toggle[%s]" data-openimage="assets/arrowup.jpg" data-closedimage="assets/arrowdown.jpg" style="text-decoration:none;">%s <img src="assets/arrowdown.jpg" style="vertical-align: middle;" /></a><br />
                    </div>\n"""%(groupDiv, reportDiv, row[0]))
            
            fout.write("""
                <div id="%s" class="tb2reports">
                    """%(reportDiv))
                    
            query = "select Link, LinkText from Navigation where GrandParent='Subnet' and Parent='%s' and ReportGroup='%s' order by LinkText"%(key, row[0])
            rows = db.FetchAllRows(query)
            for arow in rows:
                fout.write("""
                    <a href="%s" style="text-decoration:none;" target="contentFrame">%s</a><br />
                    """%(arow[0], arow[1]))
        
            fout.write("</div>\n")
            j +=1
            
        i += 1
        
    fout.write("<p></p><p></p>\n")
    
    #now write Individual navigation
    fout.write("""
        <a href="javascript:toggleBars('Individual', %d)" class="toggleBar">Individual System Reports</a>
        """%len(individuals))
        
    i = 1
    for row in individuals:
        indID = 'Individual%d'%(i)
        
        reportDiv = "%sReport"%indID
        fout.write("""
                <div id="%s" class="toggleBar1">
                <a href="#" rel="toggle[%s]" data-openimage="assets/arrowup.jpg" data-closedimage="assets/arrowdown.jpg" style="text-decoration:none;">%s <img src="assets/arrowdown.jpg" style="vertical-align: middle;"/></a><br />
                </div>\n"""%(indID, reportDiv, row[0]))
        
        fout.write("""
            <div id="%s" class="tb1reports">
                """%(reportDiv))
                
        query = "select Link, LinkText from Navigation where GrandParent='Individual' and Parent='%s' order by LinkText"%(row[0])
        rows = db.FetchAllRows(query)
        for arow in rows:
            fout.write("""
                <a href="%s" style="text-decoration:none;" target="contentFrame">%s</a><br />
                """%(arow[0], arow[1]))
    
        fout.write("</div>\n")
        
        i += 1

    fout.write('<p></p><p></p>\n')
    fout.write('</body>\n</html>')
    
    fout.close()
    db.CloseConnection()
    print 'Done Generating Report Browser....!'
    
if __name__ == "__main__":
    pass
    """
    ReadConfigFile()
    GenerateNavigation()
    """