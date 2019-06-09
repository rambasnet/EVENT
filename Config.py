#-----------------------------------------------------------------------------
# Name:        Config.py
# Purpose:     
#
# Author:      Ram B. Basnet
#
# Created:     2009/10/10
# RCS-ID:      $Id: Config.py $
# Copyright:   (c) 2009
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------
import os.path, sys

Config = {}

def ReadConfigFile():
    if not os.path.exists(r'assets\Config.txt'):
        print 'Not Config.txt file found! Exiting...'
        sys.exit()
        
    global Config
    fin = open(r'assets\Config.txt', 'r')
    lines = fin.readlines()
    fin.close()
    compromisedIps = False
    for line in lines:
        if line.startswith('#') or not line.strip():
            continue
        alist = line.strip().split(':', 1)
        if not compromisedIps:
            if len(alist) <= 1:
                continue
    
        
        if alist[0].startswith('CompromisedIPs') or compromisedIps:
            #print 'line ', line
            if not compromisedIps:
                key = alist[0].strip()
                Config[key] = []
                compromisedIps = True
                values = []
                for value in alist[1].split(','):
                    values.append(value.strip())
                Config[key].append(values)
                continue
            else:
                key = 'CompromisedIPs'
                values = []
                for value in alist[0].split(','):
                    values.append(value.strip())
                
                Config[key] = values
                continue
                                        
        else:
            #there's comma separted list of values
            valueList = alist[1].split(',')
            key = alist[0].strip()
            if len(valueList) > 1:
                Config[key] = []
                values = []
                for item in valueList:
                    values.append(item.strip())
                Config[key] = tuple(values)
            else:
                Config[key] = valueList[0].strip()
            
     
if __name__=="__main__":
    pass
    """
    ReadConfigFile()
    for key in Config:
        print key, '->', Config[key]
    """
