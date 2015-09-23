Shibboleth identification plugin for CKAN 2.4. 

Install
=======

You can install ckanext-shibboleth with

	pip install -e git+git://github.com/geosolutions-it/ckanext-shibboleth.git#egg=ckanext-shibboleth
	
	
Plugin configuration
====================

who.ini configuration
---------------------

Add the ``plugin:shibboleth`` section, customizing the env var names:

    [plugin:shibboleth]
    use = ckanext.repoze.who.shibboleth.plugin:make_identification_plugin
    session = Shib-Session-ID
    eppn = eppn
    mail = mail
    fullname = cn
    # Add more key-worded parameters below
    firstname = displayName
    surname = sn
    organization = homeOrganization
    mobile = mobile
    telephone = telephoneNumber

    # These are needed to find out if we are receiving info from the Shibboleth module.
    # Customize both if needed.
    check_auth_key=HTTP_SHIB_AUTHENTICATION_METHOD 
    check_auth_value=urn:oasis:names:tc:SAML:1.0:am:unspecified

Add ``shibboleth`` to the list of the identifier plugins:

    [identifiers]
    plugins =
        shibboleth
        friendlyform;browser
        auth_tkt

Add ``shibboleth`` to the list of the authenticator plugins:

    [authenticators]
    plugins =
        auth_tkt
        ckan.lib.authenticator:UsernamePasswordAuthenticator
        ckanext.repoze.who.shibboleth.extension:ShibbolethAuthenticator

Add ``shibboleth`` to the list of the challengers plugins:

    [challengers]
    plugins =
        shibboleth
    #    friendlyform;browser
    #   basicauth

production.ini configuration
----------------------------

Add ``shibboleth`` the the ckan.plugins line

     ckan.plugins = [...] shibboleth

Apache HTTPD configuration
--------------------------

The ckanext-shibboleth extension requires that the ``/shibboleth`` path to be externally filtered by the shibboleth
client module.

Using ``mod_shib`` on your apache httpd installation, you need these lines in your configuration file:

    <Location ~ /shibboleth >
        AuthType shibboleth
        ShibRequireSession On
        require valid-user
    </Location>


