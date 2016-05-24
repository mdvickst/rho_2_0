#!/usr/bin/env python

import json
import sys
import csv

report_type = sys.argv[1]

success = False

f = open('rho_results.csv', 'w+')
csv_file = csv.writer(f)
if report_type is '1':  # rhel report
    csv_file.writerow(["hostname", "socket_pairs"])
    csv_file.writerow(
        ["Red Hat Enterprise Linux Deployment Summary", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
         "", "", "", ""])
    csv_file.writerow(["Customer Name", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""])
    csv_file.writerow(
        ['Date', 'Linux Distribution', 'Release number', 'Operating System Hostname', 'IP Address', 'Physical/Virtual',
         'Physical Sockets', '"If Virtual, number of vCPUs"', '"If Virtual, Hosted by"',
         '"If Virtual, Sockets on Host"', '"If Virtual, Host Cluster name"',
         '"If Virtual, Number of Vmware Hosts in Cluster"', 'Are Red Hat Packages Installed',
         'Number of Red Hat Packages Installed', 'Last Installed RH Package',
         'Last RH Package Install Date', 'Subscription Manager Registered', 'Install Date', 'Auth Name',
         'Port', 'Error'])
    csv_file.writerow(['Date the Scan was performed', 'Name of Red Hat family of product installed',
                       'Release number of the Linux version installed', 'Hostname of the operating system reported',
                       'IP address scanned',
                       'Physical or Virtual Operating System',
                       'Number of sockets on the physical server (if applicable)',
                       'Number of virtual cpus assigned to the virtual server',
                       'Hostname of the VMware Server running the RHEL VM reported',
                       'Number of physical sockets on the Vmware server', 'Name of the VMware cluster',
                       'Number of hosts in the cluster name',
                       'Y/N on whether Red Hat Packages are Installed on the system.',
                       'Number of Red Hat Packages that are installed on the System.',
                       'The last Red Hat package to be installed on the system.',
                       'Date that the last installed Red Hat package was installed.',
                       '"Is the System Registered with Subscription Manager to RHN', ' Satellite', ' etc."',
                       'Date instance reported was installed', 'Username that was used to log into the server.',
                       'SSH Port used', 'Any Errors that occurred during scan.'])
elif report_type is '2':  # JBoss Report
    csv_file.writerow(["IP address", "hostname", "JBoss releases", "CPU Cores"])
jfile = ""
with open("/tmp/results") as f:
    for line in f:
        while True:
            if "}" in line and not success:
                line = ""
                break
            if "=>" in line:
                if "SUCCESS" in line:
                    ip = line.split("|")[0].strip()
                    line = "{"
                    line += "\"IP\": \"" + ip + "\",\n"
                    success = True
                else:
                    success = False
                    jfile = ""
                    line = ""
            try:
                if success:
                    jfile = json.loads(line)
                    break
                else:
                    try:
                        line += next(f)
                    except StopIteration:
                        break
            except ValueError:
                # Not yet a complete JSON value
                line += next(f)

        if jfile is not "":
            if report_type is '1':  # rhel report
                csv_file.writerow([jfile['date'], jfile['linuxDistribution'], jfile['releaseNumber'],
                                   jfile['operatingSystemHostname'], jfile["IP"], jfile['physicalOrVirtual'],
                                   jfile['physicalSockets'], jfile['numberofvCPUs'], jfile['hostedBy'],
                                   jfile['socketsOnHost'], jfile['hostClusterName'], jfile['numberOfHostsInCluster'],
                                   jfile['areRedHatPackagesInstalled'], jfile['numberOfRHPackagesInstalled'],
                                   jfile['lastInstalledRHPackage'], jfile['lastRHPackageInstallDate'],
                                   jfile['subscriptionManagerRegistered'], jfile['installDate'], jfile['authName'],
                                   jfile['port'], jfile['error']])
                # csv_file.writerow([jfile["hostname"], jfile["socket_pairs"]])

                # print jfile['hostname'] + " had " + jfile['socket_pairs'] + " socket pairs"
            elif report_type is '2':  # JBoss Report
                csv_file.writerow([jfile["IP"], jfile["hostname"], "\"" + jfile["releases"] + "\"", jfile["cores"]])
                print jfile['hostname'] + " had " + jfile['releases'] + " releases and " + jfile["cores"] + " CPU Cores"

        jfile = ""
f.close()
