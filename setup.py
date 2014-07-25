from setuptools import setup
import sys

install_requires = []
if sys.version_info < (2, 7):
    install_requires.append("argparse")

if sys.version_info < (3, 3):
    install_requires.append("mock")

if sys.version_info < (3, 2):
    install_requires.append('futures')

setup(
    name='dropboxhandler',
    version='1.2.0',
    author='Adrian Seyboldt',
    author_email='adrian.seyboldt@web.de',
    py_modules=['dropboxhandler'],
    entry_points={
        'console_scripts':
            ['dropboxhandler = dropboxhandler:main']
    },
    data_files=[('', ['example.conf'])],
    description='Rename and sort incoming files from dropbox',
    install_requires=install_requires,
)
