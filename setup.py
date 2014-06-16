from setuptools import setup

setup(
    name='dropboxhandler',
    version='1.0',
    author='Adrian Seyboldt',
    author_email='adrian.seyboldt@wbe.de',
    packages=['dropboxhandler'],
    entry_points={
        'console_scripts':
            ['dropboxhandler = dropboxhandler:main']
    },
    data_files=[('dropboxhandler', ['dropboxhandler/example.conf'])],
    description='Rename and sort incoming files from dropbox',
)
