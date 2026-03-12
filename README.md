# LDAP Dovecot Postlogin script

This script completely replaces Dovecot's namespaces configuration, dynamically adding namespaces per-user based on AD LDAP structure.
Compatible with Dovecot 2.4+ only.

This is not a complete product nor a ready-to use mail server configuration.
Study carefully and apply to your particular setup.
Contains some workarounds that may be not be comatible with standart configurations.
Conains some amount of vibe-code, although carefully checked by a human.
Use at your own risk.

## Features
- Full account management via AD console
- Multiple personal addresses/mailboxes per user
- Multiple addresses/mailboxes per group
- Multiple domains with individual relay hosts
- Users get access to all their personal and group mailboxes as additional namespaces
- Users can log in with any of their mail addresses, switching the primary inbox
- Users can send emails from any of their mail addresses
- Virtual folders that include all messages and all messages of that folder in all mailboxe


<img width="624" height="300" alt="dovecot-postlogin" src="https://github.com/user-attachments/assets/93cab7fc-3948-4715-9e50-7d7a283602da" />

## Installation

### Dovecot
1. Create LDAP configuration file (default: /etc/ldap/dovecot.conf) with following parameters:
```
ldap_uris = "ldaps://dc.mycompany.local:636"
ldap_version = "3"
ldap_auth_dn = "vmail@mycompany.local"
ldap_auth_dn_password = "secret"
ldap_base = "ou=company,dc=mycompany,dc=local" # Limit user search to this OU
```
2. Adjust your mail_path and home directories locations in auth-ldap-postlogin.conf.ext
3. Include auth-ldap-postlogin.conf.ext in your 10-auth.conf 
4. Enable processing of the postlogin.py script in 
```
service imap {
  executable = imap imap-postlogin
}

service imap-postlogin {
  executable = script-login /etc/dovecot/postlogin.py
  user = vmail
  unix_listener imap-postlogin {
  }
}
```
5. Apply settings from 10-mail.conf.example to your 10-mail.conf

### Postfix
1. Apply settings from main.cf.example to your main.cf
2. Adjust LDAP credentials in all ldap/*.cf files
3. If you want to use dedicated relay for each domain, adjust relay port in sender_dependent_relayhost_maps.cf.
   Otherwise, or if you would like to allow this server to send emails directly, remove relayhost = [0.0.0.0] from your config


### LDAP/AD
1. Create an OU that will be used for sharing groups (default: Departments).
2. Create an OU that will be used for groups representing relays (default: MailDomains).
3. Populete MailDomains OU with groups. Group's CN should be set to domain name, mail should be set to this domain's relay address. This is a workaround that allows use of the default schema.



## Usage
- Set user's email field to make it the primary user's address\mailbox
- Add user's proxyAddresses to give user access to additional addresses\mailboxes
- Add user's otherMailbox to set an alias for user's primary email address
- Include user into a group in sharing OU to give access to all group's addresses\mailboxes
- Set group's primary email and proxyAddresses to give all it's members access to these mailboxes

## Known issues

- Users cant have duplicate emails, otherwise the script will fail. Give email address to a group and include users in this group instead.
