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

production.ini configuration
----------------------------

Add ``shibboleth`` the the ckan.plugins line

     ckan.plugins = [...] shibboleth

Configure the URL secured with Shibboleth authentication 
     
     # Default is /shibboleth/login
     ckanext.shib.login_path = /secure 

If you want to log out from the SSO when exiting from CKAN, you have to set the ``logout_path``
to the URL that will perform the Shibboleth logout  

     # Default is /
     ckanext.shib.logout_path = /shibboleth/logout
     

who.ini configuration
---------------------

Add the ``plugin:shibboleth`` section, customizing the env var names:

    [plugin:shibboleth]
    use = ckanext.shibboleth.repoze.ident:make_identification_plugin

    session = YOUR_HEADER_FOR_Shib-Session-ID
    eppn = YOUR_HEADER_FOR_eppn
    mail = YOUR_HEADER_FOR_mail

    fullname = YOUR_HEADER_FOR_cn
    givenname = YOUR_HEADER_FOR_FIRST_NAME
    surname = YOUR_HEADER_FOR_SURNAME

    check_auth_key = YOUR_HEADER_FOR_AUTH_TYPE
    check_auth_op = "equals" | "not_empty"
    check_auth_value = YOUR_AUTH_VALUE

``check_auth_*`` keys are needed to find out if we are receiving info from the Shibboleth module. Customize both right-side values if needed. 
For instance, older Shibboleth implementations may need this configuration:

    check_auth_key=HTTP_SHIB_AUTHENTICATION_METHOD 
    check_auth_op=equals
    check_auth_value=urn:oasis:names:tc:SAML:1.0:am:unspecified

If ``check_auth_op=not_empty`` then ``check_auth_value`` is not needed.

The related CKAN user will be created using the ``fullname`` if given, or composing name and surname.
You must set at least the fullname header name, or the givenname+surname headers name, or CKAN will not be able to create a user. 

Add ``shibboleth`` to the list of the identifier plugins:

    [identifiers]
    plugins =
        shibboleth
        friendlyform;browser
        auth_tkt

Add ``ckanext.shibboleth.repoze.auth:ShibbolethAuthenticator`` to the list of the authenticator plugins:

    [authenticators]
    plugins =
        auth_tkt
        ckan.lib.authenticator:UsernamePasswordAuthenticator
        ckanext.shibboleth.repoze.auth:ShibbolethAuthenticator

Add ``shibboleth`` to the list of the challengers plugins:

    [challengers]
    plugins =
        shibboleth
    #    friendlyform;browser
    #   basicauth

Apache HTTPD configuration
--------------------------

The ckanext-shibboleth extension requires a path to be externally secured by the shibboleth
client module.  
By default it's ``/shibboleth``, but you can customize it for your needs.

Using ``mod_shib`` on your apache httpd installation, you need these lines in your configuration file:

    # Customize with your path
    <Location ~ /secure > 
        AuthType shibboleth
        ShibRequireSession On
        require valid-user
    </Location>
