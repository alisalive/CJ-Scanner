from setuptools import setup

setup(
    name='cj-scanner',
    version='2.0',
    py_modules=['cj_scanner'],
    install_requires=['requests', 'colorama', 'pyfiglet', 'beautifulsoup4', 'lxml'],
    entry_points={
        'console_scripts': [
            'cj-scanner=cj_scanner:main',
        ],
    },
)
