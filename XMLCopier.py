import os, os.path
import shutil


outPath = 'NmapXML'
if not os.path.exists(outPath):
    os.mkdir(outPath)

for root, dirs, files in os.walk('Nmap'):
    for afile in files:
        filePath = os.path.join(root, afile)
        if filePath.find('.xml') > 0:
            outFile = os.path.join(outPath, afile)
            shutil.copyfile(filePath, outFile)
            