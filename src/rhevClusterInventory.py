#!/usr/bin/env python
#
# File: rhevClusterInventory.py
# Author: Rich Jerrido <rwj@redhat.com>
# Purpose: Given a username, password, cluster and FQDN of RHEV-M, inventory said cluster
#          and return the 'hardware' makeup of the cluster (number/type of hypervisors +
#          number/type of virtual machines) 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import urllib2
import sys
import base64
import getpass
import csv
import ssl
import json
from xml.etree import ElementTree
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-l", "--login", dest="login", help="Login user for RHEV - MUST specify @domain", metavar="LOGIN")
parser.add_option("-p", "--password", dest="password", help="Password for specified user. Will prompt if omitted",
                  metavar="PASSWORD")
parser.add_option("-s", "--server", dest="serverfqdn", help="FQDN of RHEV-M - omit https://", metavar="SERVERFQDN")
parser.add_option("-o", "--port", dest="port", help="HTTPS port of RHEV-M", metavar="PORT")
parser.add_option("-c", "--cluster", dest="cluster", help="Which cluster to be inventoried", metavar="CLUSTER")
(options, args) = parser.parse_args()

if not (options.login and options.serverfqdn and options.port and options.cluster):
    print "Must specify login, server, port and cluster options.  See usage:"
    parser.print_help()
    print "\nExample usage: ./rhevClusterInventory.py -l admin@internal -s rhevm.example.com -o 443 -c MYCLUSTER"
    sys.exit(1)
else:
    login = options.login
    password = options.password
    serverfqdn = options.serverfqdn
    port = options.port
    cluster = "*"
    print options.cluster
    if options.cluster.strip() != "all":
        cluster = options.cluster

if not password:
    password = getpass.getpass("%s's password:" % login)

cluster_json = json.loads("{}")

URL = "https://" + serverfqdn + ":" + port + "/api/"
request = urllib2.Request(URL)
print "Connecting to: " + URL
base64string = base64.encodestring('%s:%s' % (login, password)).strip()
request.add_header("Authorization", "Basic %s" % base64string)

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    xmldata = urllib2.urlopen(request, context=ctx).read()
except urllib2.URLError, e:
    print "Error: cannot connect to REST API: %s" % (e)
    print "Try to login using the same user/pass by the Admin Portal and check the error!"
    sys.exit(2)

tree = ElementTree.XML(xmldata)
lst = tree.findall("summary")

for item in lst:
    numvm = item.find("vms/total").text
    numhosts = item.find("hosts/total").text

URL = "https://" + serverfqdn + ":" + port + "/api/hosts;max=" + numhosts + "?search=" + cluster

request = urllib2.Request(URL)
print "Connecting to: " + URL
base64string = base64.encodestring('%s:%s' % (login, password)).strip()
request.add_header("Authorization", "Basic %s" % base64string)
hypervisor_filename = options.cluster + "-hypervisors.csv"
guest_filename = options.cluster + "-guests.csv"
mapping_filename = options.cluster + "-mappings.csv"

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    xmldata = urllib2.urlopen(request, context=ctx).read()
    # xmldata = urllib2.urlopen(request).read()
except urllib2.URLError, e:
    print "Error: cannot connect to REST API: %s" % e
    print "Try to login using the same user/pass by the Admin Portal and check the error!"
    sys.exit(2)

tree = ElementTree.XML(xmldata)
lst = tree.findall("host")

name_list = []
socket_list = []
cores_list = []
model_list = []
vendor_list = []
uuid_list = []

for item in lst:
    name = item.find("name").text
    sockets = item.find("cpu/topology").attrib["sockets"]
    cores = item.find("cpu/topology").attrib["cores"]
    uuid = item.attrib["id"]
    model = item.find("hardware_information/manufacturer").text
    vendor = item.find("hardware_information/product_name").text
    name_list.append(name)
    socket_list.append(sockets)
    cores_list.append(cores)
    uuid_list.append(uuid)
    model_list.append(model)
    vendor_list.append(vendor)
    cluster_att = item.find("cluster").attrib["id"]
    try:
        cluster_json[cluster_att]["hosts"].append(json.loads('{"name": "' + name + '", "uuid": "' + uuid + '"}'))
    except KeyError:
        cluster_json[cluster_att] = json.loads('{"hosts": [], "vms": []}')
        cluster_json[cluster_att]["hosts"].append(json.loads('{"name": "' + name + '", "uuid": "' + uuid + '"}'))
    print "Hypervisor Found:"
    print "\t Name: %s" % name
    print "\t Sockets: %s" % sockets
    print "\t Cores: %s" % cores
    print "\t Vendor: %s" % vendor
    print "\t Model: %s" % model
    print "\t UUID: %s" % uuid

URL = "https://" + serverfqdn + ":" + port + "/api/vms;max=" + numvm + "?search=" + cluster
print URL

request = urllib2.Request(URL)
base64string = base64.encodestring('%s:%s' % (login, password)).strip()
request.add_header("Authorization", "Basic %s" % base64string)

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    xmldata = urllib2.urlopen(request, context=ctx).read()
    # xmldata = urllib2.urlopen(request).read()
except urllib2.URLError, e:
    print "Error: cannot connect to REST API: %s" % e
    print "Try to login using the same user/pass by the Admin Portal and check the error!"
    sys.exit(2)

tree = ElementTree.XML(xmldata)
lst = tree.findall("vm")

vm_list = []
vm_guest_type = []
vm_hostname_list = []
vm_guestid_list = []
vm_ipaddr_list = []
vm_vCPU_list = []
vm_created_time_list = []
vm_state_list = []

for item in lst:
    name = item.find("name").text
    ostype = item.find("os").attrib["type"]
    cores = item.find("cpu/topology").attrib["cores"]
    sockets = item.find("cpu/topology").attrib["sockets"]
    total_cores = int(cores) * int(sockets)
    created = item.find("creation_time").text
    cluster = item.find("cluster").attrib["id"]
    state = item.find("status").find("state").text
    try:
        cluster_json[cluster]["vms"].append(json.loads('{"name": "' + name + '", "created": "' + created + '", "state": "' + state + '"}'))
    except KeyError:
        cluster_json[cluster] = json.loads('{"hosts": [], "vms": []}')
        cluster_json[cluster]["vms"].append(json.loads('{"name": "' + name + '", "created": "' + created + '", "state": "' + state + '"}'))
    # IP Address is optional (So we gotta handle the exception when it isn't present)
    try:
        ip = item.find("guest_info/ips/ip").attrib["address"]
    except AttributeError as e:
        ip = "None"

    vm_list.append(name)
    vm_guest_type.append(ostype)
    vm_vCPU_list.append(total_cores)
    vm_ipaddr_list.append(ip)
    vm_created_time_list.append(created)
    vm_state_list.append(state)
    print "VM Found:"
    print "\t Name: %s" % name
    print "\t Type: %s" % ostype
    print "\t IP Address: %s" % ip
    print "\t vCPU Count: %s" % total_cores
    print "\t VM Creation Date: %s" % created

try:
    csv_writer_hypervisors = csv.writer(open(hypervisor_filename, "wb"), delimiter=';', quoting=csv.QUOTE_NONE)
    csv_writer_guests = csv.writer(open(guest_filename, "wb"), delimiter=';', quoting=csv.QUOTE_NONE)
    csv_writer_mapping = csv.writer(open(mapping_filename, "wb"), delimiter=';', quoting=csv.QUOTE_NONE)
    title_row = ['Name,Sockets,Total Cores,Vendor,Model,UUID']
    csv_writer_hypervisors.writerow(title_row)
    for i, j, k, l, m, n in zip(name_list, socket_list, cores_list, vendor_list, model_list, uuid_list):
        next_row = ["%s,%s,%s,%s,%s,%s" % (i, j, k, l, m, n)]
        csv_writer_hypervisors.writerow(next_row)

    title_row = ['Name,Type,IP Address,vCPU count,Creation Date']
    csv_writer_guests.writerow(title_row)
    for i, j, k, l, m, n in zip(vm_list, vm_guest_type, vm_ipaddr_list, vm_vCPU_list, vm_created_time_list, vm_state_list):
        next_row = ["%s,%s,%s,%s,%s,%s" % (i, j, k, l, m, n)]
        csv_writer_guests.writerow(next_row)

    for cluster in cluster_json:
        csv_writer_mapping.writerow(["Cluster_UUID", "Cluster Name"])
        csv_writer_mapping.writerow(cluster)
        csv_writer_mapping.writerow(["host_name", "host_uuid"])
        for host in cluster_json[cluster]["hosts"]:
            csv_writer_mapping.writerow([host["name"], host["uuid"]])
            print host["name"], host["uuid"]
        csv_writer_mapping.writerow(["vm_name", "vm_created", "vm_state"])
        for vm in cluster_json[cluster]["vms"]:
            csv_writer_mapping.writerow([vm["name"], vm["created"], vm["state"]])
            print vm["name"], vm["created"]

except IOError, e:
    print "ERROR - I/O error({0}): {1}".format(e.errno, e.strerror)
    print "Unable to save data to CSV"
    sys.exit(1)
