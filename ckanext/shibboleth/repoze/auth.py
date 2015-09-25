# -*- coding: utf-8 -*-
'''
Shibboleth plugin for CKAN
'''

import logging

from zope.interface import implements
from repoze.who.interfaces import IAuthenticator

from ckan.model import User


log = logging.getLogger(__name__)


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
