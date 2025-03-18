<?php
set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__file__) . '/include');
return array(
    'id' => 'auth:ldap2',  // notrans
    'version' => '0.7.0',
    'name' => /* trans */ 'LDAP Authentication and Lookup v2',
    'author' => 'Jared Hancock',
    'description' => /* trans */ 'Provides a configurable authentication backend
        which works against Microsoft Active Directory and OpenLdap
        servers',
    'url' => 'http://www.osticket.com/plugins/auth/ldap',
    'plugin' => 'authentication.php:LdapAuthPlugin2',
);

?>
