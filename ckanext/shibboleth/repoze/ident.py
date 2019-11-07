# -*- coding: utf8 -*-
'''
Repoze.who plugin for ckanext-shibboleth
'''

import logging
from urlparse import urlparse, urlunparse

from requests import Response
from webob import Request, Response
from zope.interface import implements

from repoze.who.interfaces import IIdentifier, IChallenger

from ckan.lib.helpers import url_for
import ckan.lib.base as base
import ckan.plugins.toolkit as toolkit
import ckan.model as model


log = logging.getLogger("ckanext.shibboleth")


SHIBBOLETH = 'shibboleth'

OP_NOT_EMPTY = 'not_empty'
OP_EQUALS = 'equals'


def make_identification_plugin(**kwargs):
    log.info("Creating ShibbolethIdentifierPlugin...")

    return ShibbolethIdentifierPlugin(**kwargs)


class ShibbolethIdentifierPlugin(object):
    implements(IChallenger, IIdentifier)

    def is_shib_session(self, env):

        val = env.get(self.check_auth_key, '')

        if self.check_auth_op == OP_NOT_EMPTY:
            return bool(val.strip())
        elif self.check_auth_op == OP_EQUALS:
            return val == self.check_auth_value
        else:
            return False

    def _validate_auth_params(self, key, op, value):
        ok = True
        if op not in (OP_NOT_EMPTY, OP_EQUALS):
            log.warning('Check auth operator not valid. Shibboleth auth will not work.')
            ok = False
        if key is None:
            log.warning('Check auth key not set in who.ini. Shibboleth auth will not work.')
            ok = False
        if op == OP_EQUALS and value is None:
            log.warning('Check auth values not set in who.ini. Shibboleth auth will not work.')
            ok = False
        if ok:
            if op == OP_EQUALS:
                log.info('Shibboleth auth will be identified by %s = %s', key, value)
            elif op == OP_NOT_EMPTY:
                log.info('Shibboleth auth will be identified by %s IS NOT EMPTY', key)

    def _validate_name_params(self, full, name, surname):

        if full:
            log.info('Shibboleth will use fullname to create user (%s)', full)
        else:
            if name and surname:
                log.info('Shibboleth will use givenname (%s) and surname (%s) to create user', name, surname)
            else:
                log.warning('User name/surname identification not set. Shibboleth auth will not work.')

    def __init__(self, session, eppn, mail, **kwargs):
        """
        Parameters here contain just names of the environment attributes defined
        in who.ini, not their values:
        @param session: 'Shib-Session-ID'
        @param eppn: 'eppn'
        @param organization: 'schacHomeOrganization'
        etc.
        """

        log.info("Initting ShibbolethIdentifierPlugin...")

        self.key_session = session
        self.key_eppn = eppn
        self.key_mail = mail

        self.key_fullname = kwargs.get('fullname', None)
        self.key_givenname = kwargs.get('givenname', None)
        self.key_surname = kwargs.get('surname', None)
        self._validate_name_params(self.key_fullname, self.key_givenname, self.key_surname)

        self.extra_keys = {}

        self.check_auth_key = kwargs['check_auth_key']
        self.check_auth_op = kwargs['check_auth_op']
        self.check_auth_value = kwargs['check_auth_value'] if 'check_auth_value' in kwargs else None
        self._validate_auth_params(self.check_auth_key, self.check_auth_op, self.check_auth_value)

        controller = 'ckanext.shibboleth.controller:ShibbolethController'

#        self.secured_login_url = url_for(controller=controller, action='shiblogin')
#        self.secured_logout_url = url_for(controller=controller, action='shiblogout')
        self.secured_login_url = base.config.get("ckanext.shib.login_path", "/shibboleth/login")
        self.secured_logout_url = base.config.get("ckanext.shib.logout_path", "/")
        self.ckan_login_url = url_for(controller='user', action='login')
        self.ckan_logout_url = url_for(controller='user', action='logout')

    def challenge(self, environ, status, app_headers, forget_headers):
        """
        repoze.who.interfaces.IChallenger.challenge.

        "Conditionally initiate a challenge to the user to provide credentials."

        "Examine the values passed in and return a WSGI application which causes a
        challenge to be performed.  Return None to forego performing a challenge."

        :param environ:  the WSGI environment
        :param status:  status written into start_response by the downstream application.
        :param app_headers:  the headers list written into start_response by the downstream application.
        :param forget_headers:
        :return:
        """

        log.info("ShibbolethIdentifierPlugin :: challenge")

        request = Request(environ)

        locale_default = environ.get('CKAN_LANG_IS_DEFAULT', True)
        locale = environ.get('CKAN_LANG', None)

        parsed_url = list(urlparse(request.url))
        parsed_url[0] = parsed_url[1] = ''
        requested_url = urlunparse(parsed_url)

        if not locale_default and locale and not requested_url.startswith('/%s/' % locale):
            requested_url = "/%s%s" % (locale, requested_url)

        url = self.ckan_login_url + "?%s=%s" % ("came_from", requested_url)

        if not locale_default and locale:
            url = "/%s%s" % (locale, url)

        response = Response()
        response.status = 302
        response.location = url

        log.info("Shibboleth response: %s (%s)" % (response, response.location))
        return response

    def dumpInfo(self, env):
        for key in sorted(env.iterkeys()):
            log.debug(' ENV %s -> %s', key, env[key])


    def identify(self, environ):
        """
        repoze.who.interfaces.IIdentifier.identify.

        "Extract credentials from the WSGI environment and turn them into an identity."

        This is called for every page load.

        :param environ:  the WSGI environment.
        :return:
        """

        request = Request(environ)

        log.debug("ShibbolethIdentifierPlugin :: identify ------------------------------------------------------------")

        # Logout user
        if request.path == self.ckan_logout_url:
            response = Response()

            for a, v in self.forget(environ, {}):
                response.headers.add(a, v)

            response.status = 302

            # try:
            #     url = url_for(controller='user', action='logged_out')
            # except AttributeError as e:
            #     # sometimes url_for fails
            #     log.warning('Error in url_for: %s', str(e))
            #     url = '/'

            # locale = environ.get('CKAN_LANG', None)
            # default_locale = environ.get('CKAN_LANG_IS_DEFAULT', True)
            # if not default_locale and locale:
            #     url = "/%s%s" % (locale, self.shib_logout_url)

            response.location = self.secured_logout_url
            environ['repoze.who.application'] = response

            log.info("Shibboleth user logout successful: %r" % request)
            return {}


        # Login user, if there's shibboleth headers and path is secured
        if request.path == self.secured_login_url:
            self.dumpInfo(environ)

        if self.is_shib_session(environ) and request.path == self.secured_login_url:
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

            if url:
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

    def _retrieve_fullname(self, env):
        if self.key_fullname:
            fullname = env.get(self.key_fullname, None)
            if fullname:
                return fullname

        if self.key_surname and self.key_givenname:
            name = env.get(self.key_givenname, None)
            surname = env.get(self.key_surname, None)
            if name and surname:
                return name + ' ' + surname

        log.warning('Can not retrieve user fullname. User not loaded.')
        return None

    def _get_or_create_user(self, env):

        eppn = env.get(self.key_eppn, None)
        fullname = self._retrieve_fullname(env)
        email = env.get(self.key_mail, None)

        if not eppn or not fullname:
            log.info('Environ does not contain user reference, user not loaded.')
            return None

        user = model.Session.query(model.User).autoflush(False) \
            .filter_by(openid=eppn).first()

        if user:
            # Check if user information from shibboleth has changed
            if user.fullname != fullname or user.email != email:
                log.info('User attributes modified, updating.')
                user.fullname = fullname
                user.email = email
        else:  # user is None:
            log.info('User does not exists, creating new one.')

            basename = unicode(fullname, errors='ignore').lower().replace(' ', '_')
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
            log.info('Created new user {usr}'.format(usr=user.fullname))

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
