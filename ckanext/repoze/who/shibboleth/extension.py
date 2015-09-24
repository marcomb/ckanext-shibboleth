'''
Shibboleth plugin for CKAN
'''

import logging

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
#from ckan.lib.plugins import DefaultTranslation  # CKAN 2.5 only

from zope.interface import implements
from repoze.who.interfaces import IAuthenticator

from ckan.model import User


log = logging.getLogger(__name__)


class CkanShibbolethPlugin(plugins.SingletonPlugin
    # , DefaultTranslation  # CKAN 2.5 only
    ):
    '''
    Shibboleth plugin for CKAN
    '''

    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IConfigurer)
#    plugins.implements(plugins.ITranslation)  # CKAN 2.5 only

    def update_config(self, config):
        """
        Override both IConfigurer and ITranslation
        """
        toolkit.add_template_directory(config, 'templates')
        #toolkit.add_public_directory(config, 'public')

    def before_map(self, map):
        """
        Override IRoutes.before_map()
        """
        controller = 'ckanext.repoze.who.shibboleth.controller:ShibbolethController'
        map.connect('shibboleth',
                    '/shibboleth/login',
                    controller=controller,
                    action='shiblogin')
        return map


class ShibbolethAuthenticator(object):
    '''
    This class implements functions for repoze, and it's declared in the who.ini file.
    '''

    implements(IAuthenticator)

    def authenticate(self, environ, identity):

        if 'shibboleth_auth' in identity:
            userid = identity['shibboleth_auth']
            user = User.get(userid)
            if user is None or not user.is_active():
                log.info("ShibbolethAuthenticator: user not found: %s", userid)
                return None
            else:
                log.info("ShibbolethAuthenticator: user found %s", userid)
                return user.name
        return None