#!/usr/bin/python
from setuptools import setup, find_packages
from setuptools.command import install as _install

class ExampleCommand(_install.install):
    description = "Runs the example application"

    _install.install.user_options.append(
        (
            'config-file=',
            'c',
            'The configuration file containing the app and SAML settings',
            ),
        )

    def initialize_options(self):
        self.config_file = None
        _install.install.initialize_options(self)

    def finalize_options(self):
        if self.config_file is None:
            self.config_file = 'example.cfg'

        _install.install.finalize_options(self)

    def run(self):
        if self.distribution.install_requires:
            self.distribution.fetch_build_eggs(
                self.distribution.install_requires,
                )

        import example
        example.main(self.config_file)

install_requires = [
        'lxml>=2.3',
        ]
tests_require = [
        'fudge >=0.9.5',
        'nose >= 0.10.4',
        ]

print find_packages()

setup(
    name='idporten.saml',
    version='0.0.4',
    description="Python client library for ID-porten SAML Version 2.0",
    packages = find_packages(),
    namespace_packages = ['idporten'],
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={'tests': tests_require},
    test_suite='nose.collector',
    cmdclass={
        'example': ExampleCommand
        },
    author='Kristian Bendiksen, Trond Kandal',
    author_email='kristian.bendiksen@gmail.com, Trond.Kandal@ntnu.no',
    url='https://git.it.ntnu.no/projects/BAS/repos/python-saml-idporten/browse',
    )
