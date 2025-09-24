from setuptools import setup, find_packages

setup(
    name='phishguard',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'phishguard=phishguard.cli.main:main',
        ],
    },
)
