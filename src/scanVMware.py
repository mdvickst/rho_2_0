#!/usr/bin/env python


"""
 File: vSphereClusterInventory.py
 Author: Rich Jerrido <rwj@redhat.com>
 Purpose: Given a username, password, cluster and FQDN of vSphere, inventory said cluster
    and return the 'hardware' makeup of the cluster (number/type of hypervisors +
    number/type of virtual machines) 
"""

import sys
import atexit
import argparse
import getpass
import csv
import ssl

from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim


def get_args():
    """Get command line args from the user.
    """
    parser = argparse.ArgumentParser(
        description='Standard Arguments for talking to vCenter')

    # because -h is reserved for 'help' we use -s for service
    parser.add_argument('-s', '--host',
                        required=True,
                        action='store',
                        help='vSphere service to connect to')

    # because we want -p for password, we use -o for port
    parser.add_argument('-o', '--port',
                        type=int,
                        default=443,
                        action='store',
                        help='Port to connect on')

    parser.add_argument('-u', '--user',
                        required=True,
                        action='store',
                        help='User name to use when connecting to host')

    parser.add_argument('-p', '--password',
                        required=False,
                        action='store',
                        help='Password to use when connecting to host')

    args = parser.parse_args()

    if not args.password:
        args.password = getpass.getpass(
            prompt='Enter password for host %s and user %s: ' %
                   (args.host, args.user))
    return args


def print_host_info(host_system):
    """
    Print information for a particular host or recurse into a
    folder with depth protection
    @type virtual_machine: vim.HostSummary
    @param virtual_machine: vim.HostSummary you wish to print
    """
    num_of_rhel_vms = 0
    summary = host_system.summary
    print "Name           : ", summary.config.name
    print "Hardware Model : ", summary.hardware.model
    print "UUID           : ", summary.hardware.uuid
    print "CPU Model      : ", summary.hardware.cpuModel
    print "Num CPU Sockets: ", summary.hardware.numCpuPkgs
    print "Memory (Bytes) : ", summary.hardware.memorySize

    for vm in summary.host.vm:
        print "VM Name       : ", vm.summary.config.name
        print "Guest         : ", vm.guest.guestFullName
        print "Guest Family  : ", vm.guest.guestFamily
        if (vm.guest.guestFamily and "Red Hat" in vm.guest.guestFamily) or (vm.guest.guestFamily and "Red Hat" in vm.guest.guestFamily):
            num_of_rhel_vms += 1
    print summary.config.name + " had " + str(num_of_rhel_vms) + " RHEL VMs"



def print_vm_info(virtual_machine):
    """
    Print information for a particular virtual machine or recurse into a
    folder with depth protection
    @type virtual_machine: vim.VirtualMachine
    @param virtual_machine: vim.vm you wish to print
    """
    summary = virtual_machine.summary
    print "Name       : ", summary.config.name
    print "Template   : ", summary.config.template
    print "Path       : ", summary.config.vmPathName
    print "Guest      : ", summary.config.guestFullName
    print "Instance UUID : ", summary.config.instanceUuid
    print "Bios UUID     : ", summary.config.uuid
    annotation = summary.config.annotation
    if annotation:
        print "Annotation : ", annotation
    print "State      : ", summary.runtime.powerState
    if summary.guest is not None:
        ip_address = summary.guest.ipAddress
        tools_version = summary.guest.toolsStatus
        if tools_version is not None:
            print "VMware-tools: ", tools_version
        else:
            print "Vmware-tools: None"
        if ip_address:
            print "IP         : ", ip_address
        else:
            print "IP         : None"
    if summary.runtime.question is not None:
        print "Question  : ", summary.runtime.question.text
    print ""


def main():
    """
    Simple command-line program for listing the virtual machines on a system.
    """

    args = get_args()
    try:
        service_instance = connect.SmartConnect(host=args.host,
                                                user=args.user,
                                                pwd=args.password,
                                                port=int(args.port))
    except Exception as exc:
        if '[SSL: CERTIFICATE_VERIFY_FAILED]' in exc.args[1]:
            try:
                import ssl
                default_context = ssl._create_default_https_context
                ssl._create_default_https_context = ssl._create_unverified_context
                service_instance = connect.SmartConnect(host=args.host,
                                                user=args.user,
                                                pwd=args.password,
                                                port=int(args.port))
                ssl._create_default_https_context = default_context
            except Exception as exc1:
                raise Exception(exc1)
        else:
            raise Exception(exc)

    if not service_instance:
        print "Could not connect to the specified host using specified username and password"
        return -1

    atexit.register(connect.Disconnect, service_instance)

    content = service_instance.RetrieveContent()

    container = content.rootFolder  # starting point to look into
    view_type = [vim.HostSystem]  # object types to look for
    recursive = True  # whether we should look into it recursively
    container_view = content.viewManager.CreateContainerView(
        container, view_type, recursive)

    children = container_view.view
    for child in children:
        print_host_info(child)

    return 0

# Start program
if __name__ == "__main__":
    main()
