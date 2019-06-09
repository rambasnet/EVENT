#-----------------------------------------------------------------------------
# Name:        setup.py
# Purpose:     
#
# Author:      Ram Basnet
#
# Created:     2009/10/10
# RCS-ID:      $Id: setup.py $
# Copyright:   (c) 2008
# Licence:     All Rights Reserved.
#-----------------------------------------------------------------------------


from distutils.core import setup
import py2exe, sys, os
import glob

origIsSystemDLL = py2exe.build_exe.isSystemDLL

def isSystemDLL(pathname):
    if os.path.basename(pathname).lower() in ("msvcp71.dll", "dwmapi.dll"):
        return 0
    return origIsSystemDLL(pathname)

py2exe.build_exe.isSystemDLL = isSystemDLL

opts = {
     'py2exe': { "includes" : ["matplotlib.backends",  "matplotlib.backends.backend_qt4agg",
                                "matplotlib.figure","pylab", "numpy", "matplotlib.numerix.fft",
                                "matplotlib.numerix.linear_algebra", "matplotlib.numerix.random_array",
                                "matplotlib.backends.backend_tkagg"],
                 'excludes': ['_gtkagg', '_tkagg', '_agg2', '_cairo', '_cocoaagg',
                              '_fltkagg', '_gtk', '_gtkcairo', ],
                 'dll_excludes': ['libgdk-win32-2.0-0.dll',
                                  'libgobject-2.0-0.dll']
               }
        }


data_files = [(r'mpl-data', glob.glob(r'C:\Python25\Lib\site-packages\matplotlib\mpl-data\*.*')),
                     # Because matplotlibrc does not have an extension, glob does not find it (at least I think that's why)
                     # So add it manually here:
                   (r'mpl-data', [r'C:\Python25\Lib\site-packages\matplotlib\mpl-data\matplotlibrc']),
                   (r'mpl-data\images',glob.glob(r'C:\Python25\Lib\site-packages\matplotlib\mpl-data\images\*.*')),
                   (r'mpl-data\fonts',glob.glob(r'C:\Python25\Lib\site-packages\matplotlib\mpl-data\fonts\*.*')),
                (r'assets', 
                    [r'assets\EVENT.ico',
                    r'assets\animatedcollapse.js',
                    r'assets\arrowdown.jpg', 
                    r'assets\arrowup.jpg',
                    r'assets\bar1bg.jpg',
                    r'assets\jquery.min.js',
                    r'assets\yes.gif',
                    r'assets\no.gif',
                    r'assets\styles.css',
                    r'assets\Config.txt',
                    r'assets\DShieldTopPorts.txt',
                    ])
            ]
                    
myrevisionstring = "Internal Rev 2.0"
setup(console=[{'script': 'EVENT.py',
            'other_resources': [(u"VERSIONTAB", 2, myrevisionstring)],
            'icon_resources': [(1, r'assets\EVENT.ico')]
            }],
            name = 'EVENT',
            version = "2.0",
            description = 'Network Security Reports Consolidator',
            author = 'Ram Basnet',
            author_email = 'rambasnet@gmail.com',
            data_files = data_files,
            options = opts
            )