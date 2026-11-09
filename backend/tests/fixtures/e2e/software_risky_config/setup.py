"""Benign end-to-end fixture: an install hook that does nothing. Parsed only, never run."""

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)


setup(name="e2e-software-risky-config", cmdclass={"install": PostInstall})
