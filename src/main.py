#!/usr/bin/env python

import menu
import getpass
import os
from netaddr import *
import netaddr
import ipaddress
import json
import crypto
import rho_config
import paramiko
import sys
import gettext
import ansible_rho
from subprocess import PIPE, Popen

t = gettext.translation('rho', 'locale', fallback=True)
_ = t.ugettext

DEFAULT_RHO_CONF = "~/.rho.conf"


def _read_key_file(filename):
    keyfile = open(os.path.expanduser(
        os.path.expandvars(filename)), "r")
    sshkey = keyfile.read()
    keyfile.close()
    return sshkey


# figure out if a key is encrypted
# basically, just try to read the key sans password
# and see if it works... Pass in a passphrase to
# see if it is the correct passphrase


def ssh_key_passphrase_is_good(filename, password=None):
    good_key = True
    try:
        if get_key_from_file(filename, password=password) is None:
            good_key = False
    except paramiko.PasswordRequiredException:
        good_key = False
    except paramiko.SSHException:
        good_key = False
    return good_key


def get_key_from_file(filename, password=None):
    pkey = None
    try:
        keyfile = open(os.path.expanduser(os.path.expandvars(filename)), "r")
        if keyfile.readline().find("-----BEGIN DSA PRIVATE KEY-----") > -1:
            keyfile.seek(0)
            pkey = paramiko.DSSKey.from_private_key_file(filename, password=password)
        keyfile.seek(0)
        if keyfile.readline().find("-----BEGIN RSA PRIVATE KEY-----") > -1:
            keyfile.seek(0)
            pkey = paramiko.RSAKey.from_private_key_file(filename, password=password)
        return pkey
    except IOError as e:
        print_error("Error opening Specified SSH Key File" + filename)
        return None


def get_passphrase(for_key):
    passphrase = getpass.getpass(_("Passphrase for '%s':" % for_key))
    return passphrase


def parse_network(net):
    try:
        ip = IPAddress(net)
    except ValueError:
        try:
            ip = IPNetwork(net)
        except ipaddress.NetmaskValueError as e:
            print e
            return None
    except netaddr.core.AddrFormatError as e:
        print e
        return None
    return ip


def print_error(error_text):
    print "\033[0;31m" + error_text + "\033[0m"
    return raw_input("\033[01;36mPlease Press 'Enter' to Return to the menu\033[0m")


def get_raw_input(prompt):
    return raw_input("\033[01;36m" + prompt + "\033[0m")


def get_password(prompt):
    return getpass.getpass("\033[01;36m" + prompt + "\033[0m")


class CalledProcessError(Exception):
    """This exception is raised when a process run by check_call() or
    check_output() returns a non-zero exit status.
    The exit status will be stored in the returncode attribute;
    check_output() will also store the output in the output attribute.
    """

    def __init__(self, returncode, cmd, output=None):
        self.returncode = returncode
        self.cmd = cmd
        self.output = output

    def __str__(self):
        return "Command '%s' returned non-zero exit status %d" % (self.cmd, self.returncode)


def get_output(cmd):
    process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    (std_output, std_error) = process.communicate()

    output = std_output.strip()

    returncode = process.poll()
    if returncode:
        raise CalledProcessError(returncode, cmd, output=output)

    return output


def quit_rho():
    sys.exit()


class Main(object):
    def __init__(self):
        self.config_file_path = os.path.abspath(os.path.expanduser(DEFAULT_RHO_CONF))

        if os.path.exists(self.config_file_path):
            self.encryption_passwd = get_password("Please enter your rho config encryption password: ")
        else:
            self.encryption_passwd = get_password(
                "Please create a new password that will be used to encrypt/decrypt the rho configuration: ")
            encryption_passwd2 = get_password("Please enter that password again: ")
            while self.encryption_passwd != encryption_passwd2:
                self.encryption_passwd = get_password(
                    "Please create a new password that will be used to encrypt/decrypt the rho configuration: ")
                encryption_passwd2 = get_password("Please enter that password again: ")

        # load or create the configuration file
        self.configuration = self.load_config(self.config_file_path, self.encryption_passwd)

        # if password not accepted and config is not returned re-prompt for password and try again
        while self.configuration is None:
            self.encryption_passwd = get_password("Please enter your rho config encryption password: ")
            self.configuration = self.load_config(self.config_file_path, self.encryption_passwd)

        self.selected_profile = None

        main_options = [{"name": "Select Profile", "function": self.select_profile},
                        {"name": "List Profiles", "function": self.list_profiles},
                        {"name": "Add Profile", "function": self.add_profile},
                        {"name": "Delete Profile", "function": self.delete_profile},
                        # {"name": "Edit Profile", "function": self.edit_profile},
                        {"name": "Dump Config (warning this will contain passwords in clear text)",
                         "function": self.dump_config},
                        {"name": "Quit", "function": quit_rho}]

        profile_options = [{"name": "Add IP or Network to Scan", "function": self.add_network},
                           {"name": "List IP Addresses and/or Networks", "function": self.print_networks},
                           {"name": "Delete IP Address or Network", "function": self.delete_network},
                           {"name": "Add Username/Password to Use", "function": self.add_user_with_pword},
                           {"name": "Add Username/SSH Key", "function": self.add_user_with_key},
                           {"name": "List Userames (Passwords will not be shown)", "function": self.list_user_names},
                           {"name": "Delete Username/Password", "function": self.delete_username},
                           {"name": "Run Scan for RHEL", "function": self.run_rhel_scan},
                           {"name": "Run Scan for JBoss", "function": self.run_jboss_scan},
                           {"name": "Scan vCenter", "function": self.scan_vcenter},
                           {"name": "Scan RHEV", "function": self.scan_rhev},
                           {"name": "Select a different Profile", "function": self.load_main_menu},
                           {"name": "Quit", "function": quit_rho}]

        self.ansible = ansible_rho.AnsibleCore()

        self.main_menu = menu.Menu("\033[0;31mRho 2.0 - Main Menu \n\033[0;34mPlease select a profile or create a "
                                   "profile to begin\033[0m")
        self.main_menu.addOptions(main_options)
        self.main_menu.submenu = menu.Menu("\033[0;31mRho 2.0 - Profile Menu\033[0m")
        self.main_menu.submenu.addOptions(profile_options)
        self.main_menu.open()

    def load_config(self, filename, password):
        if os.path.exists(filename):
            try:
                confstr = crypto.read_file(filename, password)
            except crypto.DecryptionException:
                print_error("Error decrypting configuration file")
                return

            try:
                return rho_config.ConfigBuilder().build_config(confstr)
            except rho_config.BadJsonException:
                print_error("Cannot parse configuration, check encryption password")
                return

        else:
            new_config = rho_config.Config()
            print "Creating new config file " + self.config_file_path
            self.write_config(new_config)
            return new_config

    def load_main_menu(self):
        self.main_menu.open()

    def write_config(self, new_config=None):
        if new_config is None:
            new_config = self.configuration
        c = rho_config.ConfigBuilder().dump_config(new_config)
        crypto.write_file(self.config_file_path, c, self.encryption_passwd)

    def select_profile(self):
        profiles = self.printer('profiles')
        if profiles is None or profiles.__len__() < 1:
            print_error("****No profiles defined yet.")
            return
        index_to_select = get_raw_input("Please input a number of the profile you want to use: ")
        try:
            self.selected_profile = profiles[int(index_to_select) - 1]
        except IndexError:
            print_error("Invalid selection, the number you input was not a valid entry.")
            return
        except ValueError:
            print_error("There was an error processing your selection. Please make sure you are entering an "
                        "index number")
            return
        self.main_menu.submenu.open()

    def list_profiles(self):
        self.printer("profiles")
        get_raw_input("Please Press 'Enter' to Return to the menu")

    def add_profile(self):
        name = get_raw_input("Please provide a name for this profile: ")

        new_profile = rho_config.Profile(name, [], [], [22])
        self.configuration.add_profile(new_profile)

        self.write_config()

    def delete_profile(self):
        profiles = self.printer('profiles')
        if profiles is None or profiles.__len__() < 1:
            return
        index_to_del = get_raw_input("Please input a number of the profile you want to delete"
                                     " (or x to return to the menu): ")
        if index_to_del == 'x':
            return
        try:
            profile = profiles[int(index_to_del) - 1]
            self.configuration.remove_profile(profile.name)
            self.write_config()
            print "Deleted Profile: " + profile.name
        except IndexError:
            print_error("Invalid selection, the number you input was not a valid entry.")
        except ValueError:
            print_error("There was an error processing your selection. Please make sure you are entering an "
                        "index number.")
            return

    def printer(self, attr='profiles'):
        attributes = None
        if attr is 'profiles':
            attributes = self.configuration.list_profiles()
        elif attr is 'networks':
            attributes = self.selected_profile.networks
        elif attr is 'auths':
            attributes = self.selected_profile.auths
        elif attr is 'ports':
            attributes = self.selected_profile.ports
        if attributes is None or attributes.__len__() < 1:
            print _("No %s defined yet" % attr)
            return None
        index = 1

        for attribute in attributes:
            if attr is 'profiles':
                print str(index) + ") " + attribute.name
            elif attr is 'networks':
                print str(index) + ") " + attribute
            elif attr is 'auths':
                print str(
                    index) + ") " + attribute.name + " | username: " + attribute.username + " | type: " + attribute.type
            elif attr is 'ports':
                print str(index) + ") " + attribute
            index += 1
        return attributes

    def edit_profile(self):
        profiles = self.printer('profiles')
        if profiles is None or profiles.__len__() < 1:
            print_error("****No profiles defined yet.")
            return
        index_to_edit = get_raw_input("Please input a number of the profile you want to edit: ")
        try:
            print "not yet implemented but would edit profile name:" + profiles[int(index_to_edit) - 1].name
            self.write_config()
        except IndexError:
            print_error("Invalid selection, the number you input was not a valid entry.")
        except ValueError:
            print_error("There was an error processing your selection. Please make sure you are entering an index "
                        "number")
            return

    def dump_config(self):
        try:
            content = crypto.read_file(self.config_file_path, self.encryption_passwd)
        except crypto.DecryptionException:
            print_error("Error decrypting configuration file")
            return
        print(json.dumps(json.loads(content), sort_keys=True, indent=4))
        get_raw_input("Please Press 'Enter' to Return to the menu")

    def add_network(self):
        network = get_raw_input(
            "Please input IP Address (x.x.x.x), IP address range (x.x.x.x-y.y.y.y), or Network in CIDR Format "
            "(x.x.x.x/y):")
        if '-' in network:
            for ip in network.split('-'):
                if parse_network(ip) is None:
                    print "Error parsing network range, one of the ranges was not a valid IP"
                    return
        elif parse_network(network) is None:
            print_error("Error parsing IP address or network in CIDR format was in the format x.x.x.x or y.y.y.y/24")
            return

        self.selected_profile.add_network(network)
        self.write_config()

    def print_networks(self):
        self.printer('networks')
        get_raw_input("Please Press 'Enter' to Return to the menu")

    def delete_network(self):
        networks = self.printer('networks')
        if networks is None:
            return
        selected_index = get_raw_input("*** Please Select a IP Address/Network to delete"
                                       " (or x to return to the menu): ")
        if selected_index == 'x':
            return
        try:
            network = networks[int(selected_index) - 1]
            self.selected_profile.remove_network(network)
            self.write_config()
            print "Deleted network: " + network
        except IndexError:
            print_error("Invalid selection, the number you input was not a valid entry.")
        except ValueError:
            print_error("There was an error processing your selection. Please make sure you are entering an "
                        "index number")
            return

    def _validate_key_and_passphrase(self, ssh_key_path):
        self.auth_passphrase = ""
        # if key works sans a password, we dont need one
        if not ssh_key_passphrase_is_good(ssh_key_path):
            self.auth_passphrase = get_passphrase(ssh_key_path)
            # validate the passphrase for the key is correct
            if not ssh_key_passphrase_is_good(ssh_key_path, self.auth_passphrase):
                print_error(_("Wrong passphrase for %s" % ssh_key_path))
                sys.exit(1)

    def _save_cred(self, cred):
        self.selected_profile.add_auth(cred)
        self.write_config()

    def add_user_with_pword(self):
        auth_name = get_raw_input("Name to reference this Username/Password Combination By (e.g. root1 or root_DMZ): ")
        username = get_raw_input("SSH Username: ")
        password = get_password("SSH Password: ")

        cred = rho_config.SshAuth({"name": auth_name,
                                   "username": username,
                                   "password": password,
                                   "type": "ssh"})
        self._save_cred(cred)

    def add_user_with_key(self):
        auth_name = get_raw_input("Name to reference this Username/Password Combination By (e.g. root1 or root_DMZ): ")
        username = get_raw_input("Username: ")
        ssh_key_path = get_raw_input("Path to SSH Key: ")

        # using sshkey
        self._validate_key_and_passphrase(ssh_key_path)
        sshkey = _read_key_file(ssh_key_path)

        cred = rho_config.SshKeyAuth({"name": auth_name,
                                      "key": sshkey,
                                      "username": username,
                                      "password": self.auth_passphrase,
                                      "type": "ssh_key"})

        self._save_cred(cred)

    def list_user_names(self):
        self.printer('auths')
        get_raw_input("Please Press 'Enter' to Return to the menu")

    def delete_username(self):
        auths = self.printer('auths')
        if auths is None or auths.__len__() < 1:
            return
        user_to_del = get_raw_input("Please enter the number of the username to delete:  (or x to return to the menu)")
        if user_to_del == 'x':
            return
        try:
            auth = auths[int(user_to_del) - 1]
            self.selected_profile.remove_auth(auth)
            self.write_config()
            print "Deleted Authentication: " + auth.name
        except IndexError:
            print_error("Invalid selection, the number you input was not a valid entry.")
            return
        except ValueError:
            print_error("There was an error processing your selection. Please make sure you are entering an "
                        "index number.")
            return

    def run_scan(self, scan_type='rhel'):
        results_file = open("/tmp/results", 'w')
        list_of_hosts = ""

        for network in self.selected_profile.networks:
            if list_of_hosts != "":
                list_of_hosts += ","
            if '-' in network:  # network range we need to split this into a format nmap will understand
                start_ip, end_ip = network.split("-")
                start_oct1, start_oct2, start_oct3, start_oct4 = start_ip.split(".")
                end_oct1, end_oct2, end_oct3, end_oct4 = end_ip.split(".")
                network = _("%s-%s.%s-%s.%s-%s.%s-%s" % start_oct1 % end_oct1 % start_oct2 % end_oct2 % start_oct3
                            % end_oct3 % start_oct4 % end_oct4)

            print _("*** Discovering Servers with SSH Port 22 Open on Network %s ***" % network)
            try:
                list_of_hosts += get_output("nmap -p 22 -Pn -n --open " + network +
                                            " | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'")
            except CalledProcessError as e:
                continue
        print list_of_hosts
        for auth in self.selected_profile.auths:
            self.ansible.run_scan(auth, list_of_hosts.replace("\n", ","), scan_type)
        get_raw_input("Please Press 'Enter' to Return to the menu")

    def run_rhel_scan(self):
        self.run_scan('rhel')

    def run_jboss_scan(self):
        self.run_scan('jboss')

    def scan_vcenter(self):
        vcenter_port = 443
        vcenter_username = get_raw_input("Username (including @domain): ")
        vcenter_password = get_password("Password: ")
        vcenter_fqdn = get_raw_input("vCenter FQDN: ")
        print "scan_vcenter " + vcenter_username + vcenter_password + vcenter_fqdn + str(vcenter_port)

    def scan_rhev(self):
        rhev_username = str(get_raw_input("Username (including @domain): "))
        rhev_password = get_password("Password: ")
        rhev_fqdn = get_raw_input("vCenter FQDN: ")
        rhev_port = get_raw_input("Cluster Name or 'all': ")
        cluster = get_raw_input("Cluster Name or 'all': ")
        print "scan_rhev " + rhev_username + rhev_password + rhev_fqdn + rhev_port + cluster


if __name__ == '__main__':
    Main()
