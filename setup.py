#!/usr/bin/env python

from setuptools import setup

setup(name='zonecheck',
      version='1.0.3',
      description='Librarys to check zones configuered on a server are working',
      author='John Bond',
      author_email='pypi@johnbond.org',
      url='https://github.com/icann-dns/zonecheck',
      license='Apache-2.0',
      packages=['zonecheck'],
      keywords='dns',
      install_requires=[
          'dnspython'
          ],
      scripts=[
          'bin/zonecheck',
          'bin/axfrcheck',
          ],
     )
