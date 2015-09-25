# -*- coding: utf8 -*-
'''
Repoze.who plugin for ckanext-shibboleth
'''

import logging

from repoze.who.interfaces import IIdentifier, IChallenger

from webob import Request, Response
from zope.interface import implements

from ckan.lib.helpers import url_for
import ckan.plugins.toolkit as toolkit

import ckan.model as model

from urlparse import urlparse, urlunparse


log = logging.getLogger("ckanext.shibboleth")


SHIBBOLETH = 'shibboleth'


def make_identification_plugin(**kwargs):
    log.info("Creating ShibbolethIdentifierPlugin...")

    return ShibbolethIdentifierPlugin(**kwargs)


class ShibbolethIdentifierPlugin(object):
    implements(IChallenger, IIdentifier)

    def is_shib_session(self, env):
        #return env.get(self.session, False) and
        return env.get(self.check_auth_key, '') == self.check_auth_value

    def __init__(self, session, eppn, mail, fullname, **kwargs):
        '''
        Parameters here contain just names of the environment attributes defined
        in who.ini, not their values:
        @param session: 'Shib-Session-ID'
        @param eppn: 'eppn'
        @param organization: 'schacHomeOrganization'
        etc.
        '''

        log.info("Initting ShibbolethIdentifierPlugin...")

        self.session = session
        self.eppn = eppn
        self.mail = mail
        self.fullname = fullname
        self.extra_keys = {}

        self.check_auth_key = kwargs['check_auth_key']
        self.check_auth_value = kwargs['check_auth_value']

        if(self.check_auth_key is None or self.check_auth_value is None):
            log.warning('Check auth values not set in who.ini. Shibboleth auth will not work.')
        else:
            log.info('Shibboleth auth will be identified by %s = %s', self.check_auth_key, self.check_auth_value)

        controller = 'ckanext.shibboleth.controller:ShibbolethController'

        self.login_url = url_for(controller=controller, action='shiblogin')
        self.login_form_url = url_for(controller='user', action='login')
        self.logout_url = url_for(controller='user', action='logout')

    def challenge(self, environ, status, app_headers, forget_headers):
        '''
        repoze.who.interfaces.IChallenger.challenge.

        "Conditionally initiate a challenge to the user to provide credentials."

        "Examine the values passed in and return a WSGI application which causes a
        challenge to be performed.  Return None to forego performing a challenge."

        :param environ:  the WSGI environment
        :param status:  status written into start_response by the downstream application.
        :param app_headers:  the headers list written into start_response by the downstream application.
        :param forget_headers:
        :return:
        '''

        log.info("ShibbolethIdentifierPlugin :: challenge")

        request = Request(environ)

        locale_default = environ.get('CKAN_LANG_IS_DEFAULT', True)
        locale = environ.get('CKAN_LANG', None)

        parsed_url = list(urlparse(request.url))
        parsed_url[0] = parsed_url[1] = ''
        requested_url = urlunparse(parsed_url)

        if not locale_default and locale and not requested_url.startswith('/%s/' % locale):
            requested_url = "/%s%s" % (locale, requested_url)

        url = self.login_form_url + "?%s=%s" % ("came_from", requested_url)

        if not locale_default and locale:
            url = "/%s%s" % (locale, url)

        response = Response()
        response.status = 302
        response.location = url

        log.info("Shibboleth response: %s (%s)" % (response, response.location))
        return response

    def dumpInfo(self, env):

        for k, v in env.iteritems():
            log.debug(' ENV %s -> %s', k, v)

    def identify(self, environ):
        """
        repoze.who.interfaces.IIdentifier.identify.

        "Extract credentials from the WSGI environment and turn them into an identity."

        This is called (twice) for every page load.

        :param environ:  the WSGI environment.
        :return:
        """

        request = Request(environ)

        #log.info("ShibbolethIdentifierPlugin :: identify")
        #log.info("auth -> %s", environ.get(self.check_auth_key, '-'))
        if (environ.get(self.check_auth_key, '') == self.check_auth_value):
            log.debug("Session is %r", environ.get(self.session, False))
            log.debug("is_shibboleth is %r", self.is_shib_session(environ))
            log.debug("request path: %s  request url: %s", request.path, self.login_url)
            self.dumpInfo(environ)

        # Logout user
        if request.path == self.logout_url:
            response = Response()

            for a, v in self.forget(environ, {}):
                response.headers.add(a, v)

            response.status = 302

            try:
                url = url_for(controller='user', action='logged_out')
            except AttributeError as e:
                # sometimes url_for fails
                log.warning('Error in url_for: %s', str(e))
                url = '/'

            locale = environ.get('CKAN_LANG', None)
            default_locale = environ.get('CKAN_LANG_IS_DEFAULT', True)
            if not default_locale and locale:
                url = "/%s%s" % (locale, url)

            response.location = url
            environ['repoze.who.application'] = response

            log.info("Shibboleth user logout successful: %r" % request)
            return {}

        # Login user, if there's shibboleth headers and path is shiblogin
        if self.is_shib_session(environ) and request.path == self.login_url:
            user = self._get_or_create_user(environ)

            if not user:
                return {}

            # TODO: Fix flash message later, maybe some other place
            #h.flash_success(
            #    _('Profile updated or restored from {idp}.').format(
            #        idp=environ.get('Shib-Identity-Provider',
            #                        'IdP not aquired')))
            response = Response()
            response.status = 302

            url = request.params.get('came_from', None)
            if not url:
                try:
                    url = toolkit.url_for(controller='package', action='search')
                except AttributeError as e:
                    # sometimes url_for fails
                    log.warning('Error in url_for: %s', str(e))
                    url = '/'

                locale = environ.get('CKAN_LANG', None)
                default_locale = environ.get('CKAN_LANG_IS_DEFAULT', True)
                if not default_locale and locale:
                    url = "/%s%s" % (locale, url)

            response.location = url
            environ['repoze.who.application'] = response

            log.info("Shibboleth login successful: %r (%s)" % (user, response.location))

            return {'shibboleth_auth': user.id}

        # User not logging in or logging out, return empty dict
        return {}

    def _get_or_create_user(self, env):
        #WSGI Variables
        #Shib-Application-ID            'default'
        #Shib-Authentication-Instant    '2012-08-13T12:04:22.492Z'
        #Shib-Authentication-Method     'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        #Shib-AuthnContext-Class        'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        #Shib-Identity-Provider         'https://idp.example.com/idp/shibboleth'
        #Shib-Session-ID                '_7ec5a681e6dbae627c1cefcc7cb4d56a'
        #Shib-Session-Index             '39dafd8477850f5e0b968e3561570197f2109948c1d374a7a2b4c9a7adbf8628'
        #cn                             'My Other Self'
        #givenName                      'My Other Self'
        #mail                           'myother@self.com'

        eppn = env.get(self.eppn, None)
        fullname = env.get(self.fullname, None)
        email = env.get(self.mail, None)

        if not eppn or not fullname:
            log.debug(
                'Environ does not contain eppn or cn attributes, user not loaded.')
            return None

        user = model.Session.query(model.User).autoflush(False) \
            .filter_by(openid=eppn).first()

        # Check if user information from shibboleth has changed
        if user:
            if (user.fullname != fullname or user.email != email):
                log.debug('User attributes modified, updating.')
                user.fullname = fullname
                user.email = email

        else:  # user is None:
            log.debug('User does not exists, creating new one.')

            basename = unicode(fullname, errors='ignore').lower().replace(' ',
                                                                          '_')
            username = basename
            suffix = 0
            while not model.User.check_name_available(username):
                suffix += 1
                username = basename + str(suffix)

            user = model.User(name=username,
                              fullname=fullname,
                              email=email,
                              openid=eppn)

            model.Session.add(user)
            model.Session.flush()
            log.info('Created new user {usr}'.format(usr=fullname))

        model.Session.commit()
        model.Session.remove()
        return user

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})
        return plugins.get('auth_tkt')

    def remember(self, environ, identity):
        '''
        Return a sequence of response headers which suffice to remember the given identity.

        :param environ:
        :param identity:
        :return:
        '''
        rememberer = self._get_rememberer(environ)
        return rememberer and rememberer.remember(environ, identity)

    def forget(self, environ, identity):
        '''
        Return a sequence of response headers which suffice to destroy any credentials used to establish an identity.

        :param environ:
        :param identity:
        :return:
        '''
        rememberer = self._get_rememberer(environ)
        return rememberer and rememberer.forget(environ, identity)
