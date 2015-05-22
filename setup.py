from setuptools import setup
import sys

install_requires = ['PyYAML', 'logutils']
if sys.version_info < (2, 7):
    install_requires.append("argparse")

if sys.version_info < (3, 2):
    install_requires.append('futures')

setup(
    name='dropboxhandler',
    version='1.5.3',
    author='Adrian Seyboldt',
    author_email='adrian.seyboldt@web.de',
    url="https://github.com/qbicsoftware/dropboxhandler",
    packages=['dropboxhandler'],
    entry_points={
        'console_scripts':
            ['dropboxhandler = dropboxhandler:main']
    },
    description='Rename and sort incoming files from dropbox',
    package_data={'dropboxhandler': ['config.yaml']},
    install_requires=install_requires,
)
