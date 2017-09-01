#!/usr/bin/env python
import os
from setuptools import setup
from setuptools.command.install import install

here = os.path.abspath(os.path.dirname(__file__))

# Generate a list of python scripts
scpts = []
scpt_dir = os.listdir(os.path.join(here, 'bin'))
for scpt in scpt_dir:
    scpts.append(os.path.join(here, 'bin', scpt))

class ScriptInstaller(install):

    """Install scripts directly."""

    def run(self):
        """Wrapper for parent run."""
        super(ScriptInstaller, self).run()

setup(name='zonecheck',
      version='1.0.18',
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
