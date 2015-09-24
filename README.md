Shibboleth identification plugin for CKAN 2.4. 

Install
=======

You can install ckanext-shibboleth either with

    pip install -e git+git://github.com/geosolutions-it/ckanext-shibboleth.git#egg=ckanext-shibboleth
	
or

    git clone https://github.com/geosolutions-it/ckanext-shibboleth.git
    python setup.py install
        
	
Plugin configuration
====================

who.ini configuration
---------------------

Add the ``plugin:shibboleth`` section, customizing the env var names:

    [plugin:shibboleth]
    use = ckanext.repoze.who.shibboleth.plugin:make_identification_plugin
    session = YOUR_HEADER_FOR_Shib-Session-ID
    eppn = YOUR_HEADER_FOR_eppn
    mail = YOUR_HEADER_FOR_mail
    fullname = YOUR_HEADER_FOR_cn

    # These are needed to find out if we are receiving info from the Shibboleth module.
    # Customize both right-side values if needed.
    check_auth_key=HTTP_SHIB_AUTHENTICATION_METHOD 
    check_auth_value=urn:oasis:names:tc:SAML:1.0:am:unspecified

Add ``shibboleth`` to the list of the identifier plugins:

    [identifiers]
    plugins =
        shibboleth
        friendlyform;browser
        auth_tkt

Add ``ckanext.repoze.who.shibboleth.extension:ShibbolethAuthenticator`` to the list of the authenticator plugins:

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


