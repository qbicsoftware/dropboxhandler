from setuptools import setup

setup(
    name='dropboxhandler',
    version='1.0',
    author='Adrian Seyboldt',
    author_email='adrian.seyboldt@wbe.de',
    #scripts=['dropboxhandler.py'],
    py_modules=['dropboxhandler'],
    entry_points={
        'console_scripts':
            ['dropboxhandler = dropboxhandler:main']
    },
    data_files=[('', ['example.conf'])],
    description='Rename and sort incoming files from dropbox',
)
