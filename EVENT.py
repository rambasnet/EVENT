#-----------------------------------------------------------------------------
# Name:        event.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2009/10/10
# RCS-ID:      $Id: event.py $
# Copyright:   (c) 2009
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------

import sys

import Parsers
import Consolidation
import Reports
import Charts
import Navigation

from Config import *

if __name__ == "__main__":
    #fout = open('EVENT.log', 'w')
    #temp = sys.stdout
    #sys.stdout = fout
    ReadConfigFile()
    #Run parsers
    
    Parsers.main()
    #Run consolidation
    Consolidation.main()
    #run reports
    Reports.main()
    #run charts
    Charts.main()
    #run navigation
    Navigation.GenerateNavigation()
    raw_input('All done! Please hit Enter key to continue...')
    #sys.stdout.close()
    #sys.stdout = temp
    