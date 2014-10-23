from setuptools import setup
import sys

assert sys.version_info >= (2, 7)

install_requires = ['PyYAML']
if sys.version_info < (2, 7):
    install_requires.append("argparse")

if sys.version_info < (3, 3):
    install_requires.append("mock")

if sys.version_info < (3, 2):
    install_requires.append('futures')

if sys.version_info < (3, 4):
    install_requires.append('pathlib')

setup(
    name='dropboxhandler',
    version='1.3.0',
    author='Adrian Seyboldt',
    author_email='adrian.seyboldt@web.de',
    url="https://github.com/qbicsoftware/dropboxhandler",
    packages=['dropboxhandler'],
    entry_points={
        'console_scripts':
            ['dropboxhandler = dropboxhandler:main']
    },
    description='Rename and sort incoming files from dropbox',
    install_requires=install_requires,
)
