<?php

require_once (INCLUDE_DIR . 'class.auth.php');

class LDAPAuthentication2
{
    var $config;
    var $type = 'staff';
    var $session;

    function __construct($config, $type = 'staff')
    {
        $this->config = $config;
        $this->type = $type;
        $this->session = strtr(base64_encode(random_bytes(15)), '+/', '-_');
    }

    function log($message)
    {
        // Log to php error log with a unique session id for correlation
        error_log(sprintf('%s %s', $this->session, $message));
    }

    function getConfig()
    {
        return $this->config;
    }

    function flatten($array)
    {
        // merge multi dimentional array down into a single
        // flat array.

        $a = array();
        foreach ($array as $e) {
            if (is_array($e)) {
                $a = array_merge($a, $this->flatten($e));
            } else {
                $a[] = $e;
            }
        }
        return $a;
    }

    public static function sanitize_servers($servers)
    {
        // Sanitize a list of servers into a consisten URI format.
        $retval = array();
        foreach ($servers as $srv) {
            if (preg_match('/^((ldaps?):\/\/)?([^:]+)(:(\d{1,5}))?(\/.*)?$/', $srv, $matches)) {
                $scheme = $matches[2] ? $matches[2] : 'ldap';
                $host = $matches[3];
                $defport = $scheme === 'ldap' ? 389 : 636;
                $port = isset($matches[5]) ? (int) $matches[5] : $defport;

                if ($port < 1 || $port > 65535) {
                    $port = $defport;
                }

                $retval[] = sprintf('%s://%s:%d/', $scheme, $host, $port);
            } else {
                error_log(sprintf($__('Invalid LDAP server entry: %s'), $srv));
            }
        }
        return $retval;
    }

    static function autodiscover($domain, $dns = array())
    {
        // Get a list of LDAP servers based on the _ldap._tcp.*
        // records in DNS.

        require_once (PEAR_DIR . 'Net/DNS2.php');
        $config = $this->getConfig();
        $q = new Net_DNS2_Resolver();
        if ($dns) {
            $q->setServers($dns);
        }

        $servers = array();
        $records = array();
        try {
            $r = $q->query('_ldap._tcp.' . $domain, 'SRV');
        } catch (Net_DNS2_Exception $e) {
            $this->log(sprintf($__('Errror looking up SRV records: %s'), $e));
            return $servers;
        }

        // Build an array that we can sort below from the SRV records
        foreach ($r->answer as $srv) {
            $records[] = array(
                'host' => "{$srv->target}:{$srv->port}",
                'priority' => $srv->priority,
                'weight' => $srv->weight,
            );
        }
        // Sort servers by priority ASC, then weight DESC
        usort($records, function ($a, $b) {
            return ($a['priority'] << 15) - $a['weight']
                - ($b['priority'] << 15) + $b['weight'];
        });
        foreach ($records as $rec) {
            $servers[] = 'ldap://' . $rec['host'];
        }
        return $this->sanitize_servers($servers);
    }

    function getServers()
    {
        // Get a sanitized list of servers that we can contact.
        // The order of the servers is their priority
        $config = $this->getConfig();
        $entries = $config->get('servers');
        if ($entries) {
            $entries = preg_split('/\s+/', $entries);
        } else {
            if ($domain = $this->getConfig()->get('domain')) {
                $dns = preg_split('/,?\s+/', $this->getConfig()->get('dns'));
                return self::autodiscover($domain, array_filter($dns));
            } else {
                $this->log($__('Unable to determine servers list'));
                $entries = array();
            }
        }
        return $this->sanitize_servers($entries);
    }

    function getConnection($force_reconnect = false)
    {
        static $connection = null;

        if ($connection && !$force_reconnect) {
            return $connection;
        }

        // Allow for self signed certs
        if ($this->getConfig()->get('noverify')) {
            putenv('LDAPTLS_REQCERT=never');
        }

        foreach ($this->getServers() as $s) {
            $c = ldap_connect($s);
            ldap_set_option($c, LDAP_OPT_TIMELIMIT, 5);
            ldap_set_option($c, LDAP_OPT_NETWORK_TIMEOUT, 5);
            ldap_set_option($c, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($c, LDAP_OPT_REFERRALS, 0);

            if ($r = $this->_bind($c)) {
                // Connection successful
                $connection = $c;
                return $c;
            } else {
                $err = ldap_error($c);
                $this->log($__('Unable to bind to %s: %s', $s, $err));
            }
        }

        $this->log($__('Unable to find a connection'));
        return false;
    }

    /**
     * Binds to the directory under the search-user credentials configured
     */
    function _bind($connection)
    {
        if (!$connection) {
            $this->log($__('_bind called without a valid connection'));
            return false;
        }
        $config = $this->getConfig();
        if ($dn = $config->get('bind_dn')) {
            $pw = Crypto::decrypt($config->get('bind_pw'), SECRET_SALT, $config->getNamespace());
            if (!($r = ldap_bind($connection, $dn, $pw))) {
                $err = ldap_error($connection);
                $this->log(sprintf($__('Error binding as user: %s'), $err));
            }
            unset($pw);
        } else {
            if (!($r = ldap_bind($connection))) {
                $err = ldap_error($connection);
                $this->log(sprintf($__('Error during anonymous binding: %s'), $err));
            }
        }
        return $r;
    }

    /**
     * Find the DN of a given user name.
     * Zero or multiple records return false.
     */
    function _finddn($user)
    {
        $dn = null;
        $c = $this->getConnection();
        if (!$c) {
            return null;
        }
        if (!$this->_bind($c)) {
            return null;
        }

        $config = $this->getConfig();

        $escaped = ldap_escape(utf8_decode($user), '', LDAP_ESCAPE_FILTER);
        $filter = str_replace('{q}', $escaped, $config->get('lookup'));
        if (!($r = ldap_search($c, $config->get('search_base'), $filter))) {
            $this->log(sprintf($__('User [%s] filter failed: %s in base %s'), $user, $filter, $config->get('search_base')));
            return null;
        }
        $entries = ldap_get_entries($c, $r);
        if ($entries['count'] == 1) {
            // Single DN found. Uniquely identify a single account
            $dn = $entries[0]['dn'];
        } elseif ($entries['count'] < 1) {
            $this->log(sprintf($__('Account does not exist: %s', $user)));
        } elseif ($entries['count'] > 1) {
            $this->log(sprintf($__('Too many records returned for account %s', $user)));
        }
        return $dn;
    }

    function authenticate($username, $password = null)
    {
        // Thanks, http://stackoverflow.com/a/764651
        // Binding with an empty password implies an anonymous bind which
        // will likely be successful and incorrect
        if (!$password) {
            return null;
        }

        // Find the user if they exist
        if (!($dn = $this->_finddn($username))) {
            $this->log(sprintf($__('No such user: %s'), $username));
            return null;
        }

        $c = $this->getConnection();
        $r = ldap_bind($c, $dn, $password);
        if (!$r) {
            $this->log(sprintf($__('LDAP failure: %s'), ldap_error($c)));
            $this->log(sprintf($__('login failed for: %s'), $dn));
            return null;
        }

        return $this->lookupAndSync($username, $dn);
    }

    function _attributes()
    {
        // Consistent function to get the LDAP attributes
        // that we care about.
        $config = $this->getConfig();

        return array_filter($this->flatten(array(
            $config->get('first'),
            $config->get('last'),
            $config->get('full'),
            $config->get('phone'),
            $config->get('mobile'),
            $config->get('email'),
            $config->get('username'),
        )));
    }

    function lookup($lookup_dn, $bind = true)
    {
        $config = $this->getConfig();
        $c = $this->getConnection();
        if ($bind && !$this->_bind($c)) {
            return null;
        }

        $attributes = $this->_attributes();
        $r = ldap_read($c, $lookup_dn, '(objectClass=*)', $this->_attributes());
        if (!$r) {
            return null;
        }

        $r = ldap_get_entries($c, $r);
        if (!$r || $r['count'] < 1) {
            return null;
        }
        return $this->_getUserInfoArray($r[0]);
    }

    function search($term)
    {
        $config = $this->getConfig();
        $c = $this->getConnection();
        $users = array();
        if (!$this->_bind($c)) {
            return $users;
        }

        $escaped = ldap_escape(utf8_decode($term), '', LDAP_ESCAPE_FILTER);
        $filter = str_replace('{q}', $escaped, $config->get('search'));
        $r = ldap_search($c, $this->getSearchBase(), $filter, $this->_attributes());

        if (!$r) {
            return $users;
        }

        $r = ldap_get_entries($c, $r);
        if (!$r || $r['count'] < 1) {
            return $users;
        }
        for ($i = 0; $i < $r['count']; $i++) {
            $users[] = $this->_getUserInfoArray($r[$i]);
        }
        return $users;
    }

    function getSearchBase()
    {
        // Get the search base from the search_base config.  If it's empty
        // then use the domain to build up a likely plausible base.
        $config = $this->getConfig();
        $base = $config->get('search_base');
        if (!$base && ($domain = $config->get('domain'))) {
            $base = 'dc=' . str_replace('.', ',dc=', $domain);
        }
        return $base;
    }

    function _getValue($entry, $name)
    {
        if (isset($entry[$name])) {
            if (isset($entry[$name]['count'])) {
                for ($i = 0; $i < $entry[$name]['count']; $i++) {
                    if (isset($entry[$name][$i]) && $entry[$name][$i]) {
                        return $entry[$name][$i];
                    }
                }
            }
        }
        return null;
    }

    function _getUserInfoArray($e)
    {
        $config = $this->getConfig();
        // Detect first and last name if only full name is given
        if (!($first = $this->_getValue($e, $config->get('first'))) ||
                !($last = $this->_getValue($e, $config->get('last')))) {
            $name = new PersonsName($this->_getValue($e, $config->get('full')));
            $first = $name->getFirst();
            $last = $name->getLast();
        } else {
            $name = "$first $last";
        }

        return array(
            'username' => $this->_getValue($e, $config->get('username')),
            'first' => $first,
            'last' => $last,
            'name' => $name,
            'email' => $this->_getValue($e, $config->get('email')),
            'phone' => $this->_getValue($e, $config->get('phone')),
            'mobile' => $this->_getValue($e, $config->get('mobile')),
            'dn' => $e['dn'],
        );
    }

    function lookupAndSync($username, $dn)
    {
        switch ($this->type) {
            case 'staff':
                if (($user = StaffSession::lookup($username)) && $user->getId()) {
                    if (!$user instanceof StaffSession) {
                        // osTicket <= v1.9.7 or so
                        $user = new StaffSession($user->getId());
                    }
                    return $user;
                }
                break;
            case 'client':
                $c = $this->getConnection();
                // Lookup all the information on the user. Try to get the email
                // addresss as well as the username when looking up the user
                // locally.
                if (!($info = $this->lookup($dn, false))) {
                    return;
                }

                $acct = false;
                foreach (array($username, $info['username'], $info['email']) as $name) {
                    if ($name && ($acct = ClientAccount::lookupByUsername($name))) {
                        break;
                    }
                }
                if (!$acct) {
                    return new ClientCreateRequest($this, $username, $info);
                }

                if (($client = new ClientSession(new EndUser($acct->getUser()))) &&
                        !$client->getId()) {
                    return;
                }

                return $client;
        }

        // TODO: Auto-create users, etc.
    }
}

class StaffLDAPAuthentication2 extends StaffAuthenticationBackend implements AuthDirectorySearch
{
    static $name = /* trans */ 'Active Directory or LDAP';
    static $id = 'ldap';

    function __construct($config)
    {
        $this->_ldap = new LDAPAuthentication2($config);
        $this->config = $config;
    }

    function authenticate($username, $password = false, $errors = array())
    {
        return $this->_ldap->authenticate($username, $password);
    }

    function getName()
    {
        $config = $this->config;
        list($__, $_N) = $config->translate();
        return $config->getName() ?: $__(static::$name);
    }

    function lookup($dn)
    {
        $hit = $this->_ldap->lookup($dn);
        if ($hit) {
            $hit['backend'] = static::$id;
            $hit['id'] = $this->getBkId() . ':' . $hit['dn'];
        }
        return $hit;
    }

    function search($query)
    {
        if (strlen($query) < 3) {
            return array();
        }

        $hits = $this->_ldap->search($query);
        foreach ($hits as &$h) {
            $h['backend'] = static::$id;
            $h['id'] = $this->getBkId() . ':' . $h['dn'];
        }
        return $hits;
    }
}

class ClientLDAPAuthentication2 extends UserAuthenticationBackend
{
    static $name = /* trans */ 'Active Directory or LDAP';
    static $id = 'ldap.client';

    function __construct($config)
    {
        $this->_ldap = new LDAPAuthentication2($config, 'client');
        $this->config = $config;
        if ($domain = $config->get('domain')) {
            self::$name .= sprintf(' (%s)', $domain);
        }
    }

    function getName()
    {
        $config = $this->config;
        list($__, $_N) = $config->translate();
        return $config->getName() ?: $__(static::$name);
    }

    function authenticate($username, $password = false, $errors = array())
    {
        $object = $this->_ldap->authenticate($username, $password);
        if ($object instanceof ClientCreateRequest) {
            $object->setBackend($this);
        }
        return $object;
    }
}

require_once (INCLUDE_DIR . 'class.plugin.php');
require_once ('config.php');

class LdapAuthPlugin2 extends Plugin
{
    var $config_class = 'LdapConfig2';

    function bootstrap()
    {
        $config = $this->getConfig();
        if ($config->get('auth-staff')) {
            StaffAuthenticationBackend::register(new StaffLDAPAuthentication2($config));
        }
        if ($config->get('auth-client')) {
            UserAuthenticationBackend::register(new ClientLDAPAuthentication2($config));
        }
    }
}
