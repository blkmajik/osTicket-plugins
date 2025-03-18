<?php

require_once (INCLUDE_DIR . '/class.plugin.php');
require_once (INCLUDE_DIR . '/class.forms.php');

// Don't strip pipes out of ldap filters.
class LdapFilterField extends TextboxField
{
    function parse($value)
    {
        return $value;
    }
}

class LdapConfig2 extends PluginConfig
{
    // Provide compatibility function for versions of osTicket prior to
    // translation support (v1.9.4)
    function translate()
    {
        if (!method_exists('Plugin', 'translate')) {
            return array(
                function ($x) {
                    return $x;
                },
                function ($x, $y, $n) {
                    return $n != 1 ? $y : $x;
                },
            );
        }
        return Plugin::translate('auth-ldap2');
    }

    function getOptions()
    {
        list($__, $_N) = self::translate();
        return array(
            'msad' => new SectionBreakField(array(
                'label' => 'LDAP Server Information',
                'hint' => $__('LDAP server information. You can choose to use
                    auto detection or enter the values for individual servers.'),
            )),
            'domain' => new TextboxField(array(
                'label' => $__('Autodetect Servers'),
                'hint' => $__("Use DNS SRV records for _ldap._tcp.* to
                    determine the LDAP servers to connect to.  If this is not
                    set you'll need to put the servers in manually below."),
                'configuration' => array('size' => 40, 'length' => 60),
                'validators' => array(
                    function ($self, $val) use ($__) {
                        if (!$val) {
                            return;
                        }
                        if (strpos($val, '.') === false) {
                            $self->addError(
                                $__('Fully-qualified domain name is expected')
                            );
                        }
                    }
                ),
            )),
            'servers' => new TextareaField(array(
                'id' => 'servers',
                'label' => $__('LDAP servers'),
                'configuration' => array('html' => false, 'rows' => 2, 'cols' => 40),
                'hint' => $__('Use ldap://server:port or ldaps://server:port. Place one server entry per line'),
            )),
            // ====================
            'tls' => new BooleanField(array(
                'id' => 'tls',
                'label' => $__('Enable STARTTLS'),
                'hint' => $__('Use STARTTLS to enable encryption with the LDAP server.
                    Use this option to create a ldap:// connection that later gets
                    encrypted with the STARTTLS command.  Typically this is used when
                    you need encryption when communicating over port 389.
                '),
                'configuration' => array(
                    'desc' => $__('Use STARTTLS for LDAP encryption.')
                ),
            )),
            'noverify' => new BooleanField(array(
                'id' => 'noverify',
                'label' => $__('Disable cert verification'),
                'configuration' => array(
                    'desc' => $__('Ignore CA verification.  Windows only.'),
                )
            )),
            // ====================
            'ldap_params' => new SectionBreakField(array(
                'label' => $__('LDAP Parameters'),
                'hint' => $__('LDAP filters and attributes'),
            )),
            'bind_dn' => new TextboxField(array(
                'label' => $__('Search User'),
                'hint' => $__('Bind DN (distinguished name) to bind to the LDAP
                    server as in order to perform searches.  Leave this blank
                    for anonymous binds.'),
                'configuration' => array('size' => 40, 'length' => 120),
            )),
            'bind_pw' => new TextboxField(array(
                'widget' => 'PasswordWidget',
                'label' => $__('Password'),
                'validator' => 'noop',
                'hint' => $__("Password associated with the DN's account"),
                'configuration' => array('size' => 40),
            )),
            'search_base' => new TextboxField(array(
                'label' => $__('Search Base'),
                'hint' => $__('Used when searching for users'),
                'configuration' => array('size' => 70, 'length' => 120),
                'placeholder' => 'ou=Users,dc=example,dc=com',
                'required' => True,
            )),
            // 'search' => new TextboxField(array(
            'search' => new LdapFilterField(array(
                'label' => $__('LDAP Search Query'),
                'hint' => $__('Used when searching for users.
                    Instances of the string "{q}" without the quotes
                    will be replaced with the search term.'),
                'configuration' => array('size' => 70, 'length' => 120),
                'placeholder' => '(&(objectClass=user)(|(sAMAccountName={q}*)(displayName={q}*)(cn={q}*)))',
                'default' => '(&(objectClass=user)(|(sAMAccountName={q}*)(displayName={q}*)(cn={q}*)))',
            )),
            // 'lookup' => new TextboxField(array(
            'lookup' => new LdapFilterField(array(
                'label' => $__('LDAP User Query'),
                'hint' => $__('Used when looking up a specific user.
                    Instances of the string "{q}" without the quotes
                    will be replaced with the query term.'),
                'configuration' => array('size' => 70, 'length' => 120),
                'placeholder' => '(&(objectClass=user)(|(sAMAccountName={q})(mail={q})))',
                'default' => '(&(objectClass=user)(|(sAMAccountName={q})(mail={q})))',
            )),
            'username' => new TextboxField(array(
                'label' => $__('User name Attribute'),
                'hint' => $__('LDAP Attribute for the login/user name
                    of a user.  Common values are sAMAccountName or uid'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'sAMAccountName',
                'default' => 'sAMAccountName',
            )),
            'first' => new TextboxField(array(
                'label' => $__('First Name Attribute'),
                'hint' => $__('LDAP Attribute for the first name of a user'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'givenName',
                'default' => 'givenName',
            )),
            'last' => new TextboxField(array(
                'label' => $__('Last Name Attribute'),
                'hint' => $__('LDAP Attribute for the last name of a user'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'sn',
                'default' => 'sn',
            )),
            'full' => new TextboxField(array(
                'label' => $__('Full Name Attribute'),
                'hint' => $__('LDAP Attribute for the full name of a user.
                    The values "displayName" and "gecos" are commonly used.'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'displayName',
                'default' => 'displayName',
            )),
            'email' => new TextboxField(array(
                'label' => $__('Email Address Attribute'),
                'hint' => $__('LDAP Attribute for the email address of a user'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'mail',
                'default' => 'mail',
            )),
            'phone' => new TextboxField(array(
                'label' => $__('Phone Number Attribute'),
                'hint' => $__('LDAP Attribute for the phone number of a user'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'telephoneNumber',
                'default' => 'telephoneNumber',
            )),
            'mobile' => new TextboxField(array(
                'label' => $__('Mobile Phone Attribute'),
                'hint' => $__('LDAP Attribute for the mobile phone number
                    of a user'),
                'configuration' => array('size' => 40, 'length' => 60),
                'placeholder' => 'mobile',
                'default' => 'mobile',
            )),
            // ====================
            'auth' => new SectionBreakField(array(
                'label' => $__('Authentication Modes'),
                'hint' => $__('Authentication modes for clients and staff
                    members can be enabled independently'),
            )),
            'auth-staff' => new BooleanField(array(
                'label' => $__('Staff Authentication'),
                'default' => true,
                'configuration' => array(
                    'desc' => $__('Enable authentication of staff members')
                )
            )),
            'auth-client' => new BooleanField(array(
                'label' => $__('Client Authentication'),
                'default' => false,
                'configuration' => array(
                    'desc' => $__('Enable authentication of clients')
                )
            )),
        );
    }

    function pre_save(&$config, &$errors)
    {
        list($__, $_N) = self::translate();

        error_log(sprintf('NUKE: Config %s', $config['search']));

        global $ost;
        if ($ost && !extension_loaded('ldap')) {
            $ost->setWarning($__('LDAP extension is not available'));
            $errors['err'] = $__('LDAP extension is not available. Please
                install or enable the `php-ldap` extension on your web
                server');
            return;
        }

        if ($config['domain'] && !$config['servers']) {
            if (!($servers = LDAPAuthentication2::autodiscover($config['domain'],
                    preg_split('/,?\s+/', $config['dns'])))) {
                $this->getForm()->getField('servers')->addError(
                    $__('Unable to find LDAP servers for this domain. Try giving
                    an address of one of the DNS servers or manually specify
                    the LDAP servers for this domain below.')
                );
            }
        } else {
            if (!$config['servers']) {
                $this->getForm()->getField('servers')->addError(
                    $__('No servers specified. Either specify a Active Directory
                    domain or a list of servers')
                );
            } else {
                $servers = LDAPAuthentication2::sanitize_servers(preg_split('/\s+/', $config['servers']));
            }
        }

        $connection_error = false;
        foreach ($servers as $srv) {
            $c = ldap_connect($srv);
            ldap_set_option($c, LDAP_OPT_TIMELIMIT, 5);
            ldap_set_option($c, LDAP_OPT_NETWORK_TIMEOUT, 5);
            ldap_set_option($c, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($c, LDAP_OPT_REFERRALS, 0);

            if ($config['tls']) {
                // Don't require a certificate here
                putenv('LDAPTLS_REQCERT=never');
                $r = ldap_start_tls($c);
                if (!$r) {
                    $connection_error = sprintf($__('STARTTLS failed to start: %s: %s'), $srv, ldap_error($c));
                    $this->getForm()->getField('servers')->addError($connection_error);
                    continue;
                }
            }

            if ($config['bind_dn']) {
                // Use supplied or saved credentials
                $r = ldap_bind($c, $config['bind_dn'], $config['bind_pw']
                    ? $config['bind_pw']
                    : Crypto::decrypt($this->get('bind_pw'), SECRET_SALT,
                        $this->getNamespace()));
            } else {
                // No credentials, do anonymous bind
                $r = ldap_bind($c);
            }
            if (!$r) {
                $err = ldap_error($c);
                $connection_error = sprintf($__('%s: Unable to bind to server %s'), $err, $srv);
                $this->getForm()->getField('servers')->addError($connection_error);
            } else {
                $connection_error = false;
                break;
            }
        }
        if ($connection_error) {
            $errors['err'] = $__('Unable to connect any listed LDAP servers');
        }

        if (!$errors && $config['bind_pw']) {
            $config['bind_pw'] = Crypto::encrypt($config['bind_pw'],
                SECRET_SALT, $this->getNamespace());
        } else {
            $config['bind_pw'] = $this->get('bind_pw');
        }

        global $msg;
        if (!$errors) {
            $msg = $__('LDAP configuration updated successfully');
        }

        return !$errors;
    }
}

?>
