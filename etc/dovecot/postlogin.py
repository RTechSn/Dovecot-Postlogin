#!/usr/bin/env python3

import os
import sys
import ldap
import time
import subprocess
import re
import tomllib

config_file = "/etc/dovecot/postlogin.conf"

with open(config_file, 'rb') as f:
    config = tomllib.load(f)

with open(config["ldap"]["ldap_config_file"], 'rb') as f:
    ldap_config = tomllib.load(f)

# ---------  Debug Functions ---------------------- #

def log(message: str):
    if config["debug"]["debug_log"]:
        # We can't output messages to stdout, it's used for dovecot commands
        sys.stderr.write(message + "\n")
        sys.stderr.flush()  # Ensure immediate output

def error(message: str):
    sys.stderr.write(message + "\n")
    sys.stderr.flush()  # Ensure immediate output


def print_dict_tree(d, indent=0):
    for key, value in d.items():
        log(' ' * indent + f"{key} (type: {type(key).__name__})")
        if isinstance(value, dict):
            print_dict_tree(value, indent + 4)  # Increase indent for nested dicts
        else:
            log(' ' * (indent + 4) + f"{value} (type: {type(value).__name__})")


def measure_time(suffix=""):
    global start_time, last_time
    try:
        start_time
    except NameError:
        start_time = time.time()
        last_time = start_time
        return  # First run, just set times

    now = time.time()
    total_execution_time = now - start_time
    execution_since_last = now - last_time
    log(f"{suffix} Total execution time since first run: {total_execution_time} seconds")
    log(f"{suffix} Execution time since last run: {execution_since_last} seconds")
    last_time = now

# --------- Initial config ------------- #

user = os.environ.get('USER')
username = user.split('@')[0]  # Remove domain part
name = os.environ.get('NAME')
home = os.environ["HOME"]
mail_path = os.environ.get('MAIL_PATH')

if not user:
    error("USER environment variable not set")
    sys.exit(1)
if not mail_path:
    error("MAIL_PATH environment variable not set")
    sys.exit(1)
if not home:
    error("HOME environment variable not set")
    sys.exit(1)
if not name:
    error("NAME environment variable not set")
    sys.exit(1)

# --- Location of user's temporary namespaces config. This config can be used with doveadm command --- #
config_path = f"{home}/dovecot-namespaces.conf"

# --- List of default mailboxes, first element is the inbox --- #
mailboxes = {
    "inbox": {
        "name": config["mailboxes"]["inbox_name"]
    },
    "sent": {
        "name": config["mailboxes"]["sent_name"],
        "special_use": "\\Sent",
        "auto": "subscribe",
    },
    "drafts": {
        "name": config["mailboxes"]["drafts_name"],
        "special_use": "\\Drafts",
        "auto": "subscribe",
    },
    "junk": {
        "name": config["mailboxes"]["junk_name"],
        "special_use": "\\Junk",
        "auto": "subscribe",
    },
    "trash": {
        "name": config["mailboxes"]["trash_name"],
        "special_use": "\\Trash",
        "auto": "subscribe",
    },
    "archive": {
        "name": config["mailboxes"]["archive_name"],
        "special_use": "\\Archive",
        "auto": "subscribe",
    },
}

mailbox_names = [mailbox["name"] for mailbox in mailboxes.values()]

log(f"name (sam): {name}")
log(f"user (login): {user}")
log(f"username: {username}")
log(f"home: {home}")
log(f"mail_path: {mail_path}")




# ---------- Functions ------------ #

def create_ldap_connection(settings_map):

    ldap_uri = ldap_config["ldap_uris"]
    bind_dn = ldap_config["ldap_auth_dn"]
    ldap_password = ldap_config["ldap_auth_dn_password"]

    try:
        conn = ldap.initialize(ldap_uri)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.simple_bind_s(bind_dn, ldap_password)
        return conn

    except ldap.LDAPError as e:
        raise Exception(f"LDAP Connection Error: {e}")


# --- Runs commands from command_list in sequence --- #
# --- You can use it to run commands during log in process --- #
def run_commands(command_list):
    # Join commands with newlines for sequential execution
    shell_script = '\n'.join(command_list)

    # Log commands being executed
    log(f"Running commands: {shell_script}")  # Replace with actual log function if needed

    try:
        # Execute commands and capture combined output
        result = subprocess.run(
            ['/bin/sh', '-c', shell_script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,                 # Return string output instead of bytes
            check=False                # Don't raise exception on non-zero exit
        )
        return result.stdout

    except Exception as e:
        error_msg = f"Execution failed: {str(e)}"
        error(error_msg)  # Replace with actual error logging function
        return error_msg


def create_mailboxes(path, mailbox_names):

    for mailbox_name in mailbox_names:
        create_mailbox(path, mailbox_name)

# --- Creates actual filesystem folders for mailboxes --- #
# --- Needed to prevent the error with virtual plugin: when a virtual mailbox not refering any actually existing mailbox, it will break
def create_mailbox(path, mailbox=None):

    # Expand tilde to home directory
    if path.startswith('~/'):
        path = path.replace('~/', f'{home}/', 1)
    if mailbox:
        mailbox_path = os.path.join(path, mailbox)
    else:
        mailbox_path = path

    log(f"Creating mailbox: {mailbox_path}")

    # Create directories
    try:
        os.makedirs(os.path.join(mailbox_path, "cur"), exist_ok=True)
        os.makedirs(os.path.join(mailbox_path, "new"), exist_ok=True)
        os.makedirs(os.path.join(mailbox_path, "tmp"), exist_ok=True)
    except OSError as e:
        error(f"Failed to create directories: {e.strerror}")


# --- Returns all email addresses for an LDAP entry --- #
def ldap_extract_emails(entry):
    emails = set()
    # Process 'mail' attribute
    if 'mail' in entry:
        for val in entry['mail']:
            if val:  # Skip empty values
                email = val.decode('utf-8').strip()
                if email:
                    emails.add(email)

    # Process 'proxyAddresses' attribute
    if 'proxyAddresses' in entry:
        for val in entry['proxyAddresses']:
            raw = val.decode('utf-8').strip()
            if not raw:
                continue

                  # Remove 'smtp:' prefix case-insensitively
            if raw.lower().startswith('smtp:'):
                email = raw[5:].strip()
            else:
                email = raw

            if email:
                emails.add(email)
    return emails


# --- Returns user's namespaces dict with all emails available to user --- #
def get_user_namespaces(username):

    conn = None
    namespaces = {}

    try:

#        ldap_config = get_ldap_settings(config["ldap"]["ldap_config_file"])
#        conn = create_ldap_connection(ldap_config)

        conn = create_ldap_connection(ldap_config)

        # Search for user with required attributes
        user_filter = f"(sAMAccountName={name})"
        user_attrs = ['mail', 'proxyAddresses', 'memberOf']
        user_results = conn.search_s(
            ldap_config["ldap_base"],
            ldap.SCOPE_SUBTREE,
            user_filter,
            user_attrs
        )
        log(f"LDAP user lookup results: {user_results}")

        # Filter out referrals (which appear as (None, ['ldap://...']))
        # We only keep entries where the DN (first element) is not None
        actual_user_results = [result for result in user_results if result[0] is not None]

        if not actual_user_results:
            return []

        # Check if multiple results are found
        if len(actual_user_results) > 1:
            # Throw an error and exit as requested
            raise Exception(f"Error: Multiple users found matching the criteria: {name}")


        # Get user's emails
        user_entry = user_results[0][1]
        user_emails = ldap_extract_emails(user_entry)
        log(f"user {user} emails: {', '.join(user_emails)}")

        # Process all groups the user is a member of
        memberOf_list = user_entry.get('memberOf', [])
        log(f"User is member of: {memberOf_list}")
        for group_dn_bytes in memberOf_list:
            group_dn = group_dn_bytes.decode('utf-8')
            if config["ldap"]["ldap_groups_filter"] not in group_dn.lower():
                #log(f"Skipping non-department group: {group_dn}")
                continue

            try:
                # Search for group details
                group_results = conn.search_s(
                    group_dn,
                    ldap.SCOPE_BASE,
                    '(objectClass=*)',
                    ['mail', 'proxyAddresses', 'cn']
                )

                if group_results:
                    group_entry = group_results[0][1]
                    group_name = group_entry.get('cn', [b''])[0].decode('utf-8', errors='replace')
                    group_emails = ldap_extract_emails(group_entry)

                    # Add shared folder
                    namespaces[group_name] = get_namespace_from_folder(f"{group_name}/", f"/mnt/mail/group_folders/{group_name}")
                    namespaces[group_name]["list"] = "children"
                    namespaces[group_name]["type"] = "public"
                    namespaces[group_name]["acl"]["user"]["rights"] = config["acl"]["rights_admin"]
#                    namespaces[group_name]["mailbox"] = {
#                                                        "trash": {
#                                                              "name": "Trash",
#                                                              "auto": "create",
#                                                              "special_use": "\Trash",
#                                                              }
#                                                        }
                    create_mailbox(f"/mnt/mail/group_folders/{group_name}")

                    log(f"Group {group_name} emails: {', '.join(group_emails)}")
                    for email in group_emails:
                        if email not in namespaces:
                            prefix = f"{group_name}/{email}/"
                            path = os.path.join(config["mailboxes"]["maildir_location"], email)

                            create_mailboxes(path, mailbox_names)
                            #set_acl(f"{prefix}{mailbox_names[0]}", permissions_read)
                            namespaces[email] = get_namespace_from_email(prefix, email)
                            namespaces[email]["type"] = "shared"
                            namespaces[email]["acl"]["user"]["rights"] = config["acl"]["rights_read"]
                            #namespaces[email]["list"] = "children"

            except ldap.LDAPError as e:
                # Log error but continue processing other groups
                error(f"Error fetching group {group_dn}: {str(e)}")
                continue


        for email in user_emails:
            if email not in namespaces:
                 path = os.path.join(config["mailboxes"]["maildir_location"], email)
                 create_mailboxes(path, mailbox_names)
                 namespaces[email] = get_namespace_from_email(f"{name}/{email}/", email)
                 namespaces[email]["acl"]["user"]["rights"] = config["acl"]["rights_admin"]

        # Disable default 'inbox' namespace
        namespaces["inbox"] = {
                               "inbox": "no",
                               "disabled": "yes"
                               }

        return namespaces

    except ldap.LDAPError as e:
        raise RuntimeError(f"LDAP error: {e}")
    finally:
        if conn:
            conn.unbind()


# ---------- Not used currently  ------------ #
def add_inbox_as_alias(namespaces):

    inbox = {
        "inbox": "yes",
        "prefix": "",
        "separator": "/",
        "list": "yes",
        "subscriptions": "yes",
        "type": "private",
        "disabled": "no",
    }

    for email, namespace in namespaces.items():
        if email == user:
            namespaces[email]["type"] = "private"
            inbox["alias_for"] = email
            inbox["mail_path"] = namespace["mail_path"]

    namespaces["inbox"] = inbox
    return namespaces

# --- Finds namespace corresponging to user's email address and sets it as the inbox --- #
def add_inbox(namespaces):

    for email, namespace in namespaces.items():
        if email == user:

            namespaces[email]["type"] = "private"
            namespaces[email]["inbox"] = "yes"
            namespaces[email]["prefix"] = ""
            namespaces[email]["subscriptions"] = "yes"
            namespaces[email]["mail_index_private_path"] = f"~/index/{email}"

            namespaces[email]["mailbox"] = mailboxes
            namespaces[email]["acl"]["user"]["rights"] = config["acl"]["rights_admin"]
    return namespaces

# --- Not used currently --- #
def get_namespaces_from_subfolders(prefix, path):

    namespaces = {}

    # Expand tilde to home directory
    if path.startswith('~/'):
        path = path.replace('~/', f'{home}/', 1)

    if not os.path.isdir(path):
        return namespaces
    for entry in os.scandir(path):
        if entry.is_dir():
            folder = entry.name
            namespaces[folder] = get_namespace_from_folder(f"{prefix}{folder}/", os.path.join(path, folder))

    return namespaces

# --- Returns configured namespace dict for given prefix and path --- #
def get_namespace_from_folder(prefix, path):

    # Give user full control of namespaces with the user's name
    if f"/{username}@" in prefix:
        type = "private"
    else:
        type = "shared"

    namespace = {
           "mail_path": path,
           "prefix": prefix,
           "separator": "/",
           "list": "yes",
           "subscriptions": "no",
           "mail_index_private_path": "~/index/" + prefix,
           "type": type,
           "acl": {
                      "user": {
                          "id": f"user={user}",
                          "rights": config["acl"]["rights_see"],
                          }
                  }
    }

    return namespace


def get_namespace_from_email(prefix, email):

    if f"/{username}@" in prefix:
        type = "private"
    else:
        type = "shared"

    #Remove path traversal symbols
    email = re.sub(r'\.\.|[/\\~]', '', email)
    namespace = {
           "mail_path": f"/mnt/mail/mailboxes/{email}",
           "prefix": prefix,
           "separator": "/",
           "list": "yes",
           "subscriptions": "no",
           "mail_index_private_path": f"~/index/{email}",
           "type": type,
           "acl": {
                      "user": {
                          "id": f"user={user}",
                          "rights": config["acl"]["rights_see"],
                          }
                  }

    }

    return namespace

# ---    Creates a persistent Dovecot configuration file from namespaces dictionary
# ---    This file can be used  as a substitude for dynamic namespaces in doveadm command
def create_dovecot_temp_config(namespaces_dict):

    # List of Dovecot named filters that require block syntax
    NAMED_FILTERS = ['acl', 'mailbox']

    # Generate new configuration content
    new_content = []
    new_content.append("dovecot_config_version = 2.4.0")
    new_content.append("dovecot_storage_version = 2.4.0")
    new_content.append("!include /etc/dovecot/dovecot.conf")

    for ns_name, ns_attrs in namespaces_dict.items():
        new_content.append(f"namespace {ns_name} {{")

        for key, value in ns_attrs.items():
            # Handle named filters (block syntax)
            if key in NAMED_FILTERS and isinstance(value, dict):
                for filter_arg, filter_settings in value.items():
                    new_content.append(f"  {key} {filter_arg} {{")

                    if isinstance(filter_settings, dict):
                        for setting_key, setting_value in filter_settings.items():
                            # Properly escape and quote values inside blocks
                            escaped_value = str(setting_value).replace("'", "'\\''")
                            new_content.append(f"    {setting_key} = '{escaped_value}'")

                    new_content.append("  }")

            else:
                # Convert non-string values to strings
                value_str = str(value)
                new_content.append(f"  {key} = {value_str}")

        new_content.append("}\n")

    new_content_str = "\n".join(new_content)

    # Check if file exists and compare content
    write_needed = True
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            existing_content = f.read()
            # Compare stripped content to ignore whitespace differences
            if existing_content.strip() == new_content_str.strip():
                write_needed = False

    # Write to file if content changed or file doesn't exist
    if write_needed:
        with open(config_path, 'w') as f:
            f.write(new_content_str)

    return config_path


# --- Sets ENV variables for Dovect to use our config --- #
def set_namespaces(namespaces, path="NAMESPACE"):
    if not namespaces:
        return

    try:
        env_keys = []
        namespace_list = []
        base_path = path.upper()  # Normalize base path to uppercase

        # Process each namespace section
        for section, config in namespaces.items():
            namespace_list.append(section.lower())
            section_upper = section.upper()

            # Recursively process configuration items
            def process_config(prefix, items):
                for key, value in items.items():
                    # Build current path with normalized key
                    current_path = f"{prefix}/{key}" if prefix else key
                    full_env_path = f"{base_path}/{section_upper}/{current_path.upper()}"

                    if isinstance(value, dict):
                        # Check if this is a named child section (all values are dicts)
                        if value and all(isinstance(v, dict) for v in value.values()):
                            # Set intermediate env var with space-separated child names
                            child_names = " ".join(value.keys())
                            os.environ[full_env_path] = child_names
                            #log(f"Set {full_env_path} = {child_names}")
                            env_keys.append(full_env_path)

                            # Process each child section
                            for child_name, child_config in value.items():
                                child_prefix = f"{current_path}/{child_name}"
                                process_config(child_prefix, child_config)
                        else:
                            # Flat section - recurse directly
                            process_config(current_path, value)
                    else:
                        # Scalar value - set env var directly
                        os.environ[full_env_path] = str(value)
                        #log(f"Set {full_env_path} = {value}")
                        env_keys.append(full_env_path)

            # Start processing with empty prefix
            process_config("", config)

        # Set NAMESPACE list variable (always uses "NAMESPACE" as Dovecot requires this)
        if namespace_list:
            os.environ["NAMESPACE"] = " ".join(namespace_list)
            #log(f"Set NAMESPACE = {os.environ['NAMESPACE']}")
            env_keys.append("NAMESPACE")

        # Update USERDB_KEYS with new variables
        if env_keys:
            current_keys = os.environ.get("USERDB_KEYS", "").split()
            seen = set()
            updated_keys = []
            for key in current_keys + env_keys:
                if key not in seen:
                    seen.add(key)
                    updated_keys.append(key)
            os.environ["USERDB_KEYS"] = " ".join(updated_keys)
            #log(f"Updated USERDB_KEYS: {os.environ['USERDB_KEYS']}")

    except Exception as e:
        error(f"Namespace configuration failed: {str(e)}")

# --- Writes dovecot-virtual file in given path --- #
# --- Pass path and list of strings, lines to be included in dovecot-virtual --- #
def generate_dovecot_virtual(path, prefixes):

    os.makedirs(path, exist_ok=True)

    # Create dovecot-virtual file path
    virtual_file = os.path.join(path, "dovecot-virtual")

    new_content = "\n".join(prefixes + ["  all"])

    # Conditional write logic
    write_needed = True
    if os.path.exists(virtual_file):
        try:
            with open(virtual_file, "r") as f:
                if f.read() == new_content:
                    write_needed = False
        except OSError as e:
            error(f"Error reading {virtual_file}: {e}")

    if write_needed:
        try:
            with open(virtual_file, "w") as f:
                f.write(new_content)
                #log(f"Updated {virtual_file} with  {' '.join(prefixes)}")
        except OSError as e:
            error(f"Error writing {virtual_file}: {e}")


# --- Get prefixes to be included in dovecot-virtual --- #
# --- Pass namespaces dict as input. Returns a list with strings - lines for dovecot-virtual --- #
def get_virtual_prefixes(namespaces):

    prefixes = []

    for ns_name, ns_config in namespaces.items():
        if "prefix" in ns_config and ns_config["prefix"]:
            prefix = ns_config["prefix"]
            #error(f"Adding prefix {prefix} for ns {ns_name}")
            prefixes.append(f"{prefix}*")

    return prefixes

# --- Get prefixes to be included in dovecot-virtual, but only given mailbox --- #
# --- Pass mailbox name and namespaces dict as input. Returns a list with strings - lines for dovecot-virtual, that include the same mailbox in each given namespace --- #
def get_virtual_prefixes_mailbox(mailbox_name, namespaces):

    prefixes = []

    prefixes.insert(0, f"!{mailbox_name}")
    for ns_name, ns_config in namespaces.items():
        #create_mailbox(os.path.join(path, mailbox))
        path = ns_config.get("mail_path")
        prefix = ns_config.get("prefix")
        if path and prefix:
            path = ns_config["mail_path"]
            prefix = ns_config["prefix"]
            if ns_name==user:
#                log(f"Found primary virtual mailbox: {mailbox_name}")
                prefixes.insert(0, f"!{prefix}{mailbox_name}")  # Insert at the beginning

            prefixes.append(f"{prefix}{mailbox_name}*")


    return prefixes

# --- Adds virtual driver as a separate namespace --- #
# --- Pass namespaces dict as input, returns  modified namespaces dict --- #
def add_virtual_namespace(namespaces):

    virtual_all_name = config['virtual']['virtual_all_name']

    prefixes = []
    prefixes.append("!INBOX")
    prefixes.append(config['mailboxes']['sent_name'])
    prefixes.extend(get_virtual_prefixes(namespaces))

    path = os.path.join(os.environ["HOME"], "virtual", user, virtual_all_name)
    generate_dovecot_virtual(path, prefixes)

    # Mirror each mailbox name as virtual
    for mailbox_name in mailbox_names:
        path = os.path.join(os.environ["HOME"], "virtual", user, virtual_all_name, mailbox_name)
        prefixes = get_virtual_prefixes_mailbox(mailbox_name, namespaces)
        generate_dovecot_virtual(path, prefixes)
    # Add virtual namespace
    virtual_dir = os.path.join(home, "virtual", user)

    namespaces["virtual"] = {
        "inbox": "no",
        "prefix": "\uFEFF", # Trick Dovecot to place our virtual namespace directly at root, not in /virtual subfolder, by using invisible BOM charater without a separator
        "separator": "/",
        "mail_driver": "virtual",
        "mail_path": virtual_dir + "/",
        "mail_index_path": f"~/index/virtual/{user}",
        "hidden": "no",
        "list": "no", # Must be "no" when there is no separator at the end of prefix.
        "mailbox": {
            "all": {
                "name": virtual_all_name,
                "auto": "subscribe",
            }
        }


    }


    return namespaces

# --- Adds virtual driver as Mailbox to given namespace --- #
# --- Pass single namespace as input, returns modified namespace --- #
# --- Unfortunately, seen flag synchronization with real doesn't work with this one :( Maybe this will be fixed later.
def add_virtual_mailbox(namespace):

    virtual_all_name = config['virtual']['virtual_all_name']

    namespace["mailbox"].update({
        "all": {
            "name": virtual_all_name,
            "auto": "subscribe",
            "mail_driver": "virtual",
            "mail_index_path": f"~/index/{virtual_all_name}",
        }
    })

    return namespace

#### ----- begin ------ ######
measure_time()
namespaces = get_user_namespaces(username)
#print_dict_tree(namespaces)
namespaces.update(add_inbox(namespaces))
namespaces.update(add_virtual_namespace(namespaces))
create_dovecot_temp_config(namespaces)
set_namespaces(namespaces)
measure_time()

#Pass to Dovecot IMAP
os.execvp(sys.argv[1], sys.argv[1:])
