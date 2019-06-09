@ECHO OFF
REM Charts.bat Generates all the charts and figures related to all the report types
:: Comment with :: to not run that line of batch script...

python Charts.pyc -r 0 -p All -s 0

FOR %%I IN (Nessus Retina Languard) DO FOR %%J IN (1 2 3) DO python Charts.pyc -r 1 -p %%I -s %%J


FOR %%I IN (3 4 5) DO python Charts.pyc -r %%I -p All -s 0

python Charts.pyc -r 6 -p Consolidation -s 0
python Charts.pyc -r 7 -p Consolidation -s 0
python Charts.pyc -r 8 -p Consolidation -s 0

ECHO Done Running Charts batch file!
PAUSE

