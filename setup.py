from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='GitlabMRScanner',
    version='0.0.3',
    packages=['gl_pr'],
    entry_points={
        'console_scripts': [
            'mr-bot = gl_pr.app:main'
        ]
    },
    license='MIT License',
    author='we45',
    author_email='info@we45.com',
    install_requires=[
        'loguru',
        'python-gitlab',
        'njsscan'
    ],
    description='Minimal Security Bot that adds security code review for Gitlab Merge Requests',
    long_description=long_description,
    long_description_content_type='text/markdown',
    include_package_data=True
)