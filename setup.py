# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

version = '1.0.0'

setup(
    name='ckanext-shibboleth',
    version=version,
    description="",
    long_description="""\
        CKAN plugin for Shibboleth authentication.
        Initially developed by CSC – IT Center for Science Ltd.
        Original repo at https://github.com/geo-solutiookata-csc/ckanext-shibboleth
        """,
    classifiers=[],
    # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='',
    author='Emanuele Tajariol',
    author_email='etj@geo-solutions.it',
    url='https://github.com/geo-solution/ckanext-shibboleth',
    license='AGPL',
    packages=find_packages(exclude=['ez_setup', 'tests']),
    namespace_packages=['ckanext',
                        'ckanext.shibboleth',
                        'ckanext.shibboleth.repoze'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    setup_requires=['nose>=1.0', 'coverage'],
    tests_require=['nose'],
    message_extractors={
        'ckanext': [
            ('**.py', 'python', None),
            ('**/templates/**.html', 'ckan', None),
            ],
    },
    entry_points={
        'ckan.plugins': [
            'shibboleth=ckanext.shibboleth.plugin:CkanShibbolethPlugin',
         ],
        'babel.extractors': [
            'ckan=ckan.lib.extract:extract_ckan',
         ],
    },
)
