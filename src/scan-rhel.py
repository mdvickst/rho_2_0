#!/usr/bin/env python

from subprocess import PIPE, Popen
from datetime import datetime
import logging
import time

__author__ = 'Mark Vickstrom'
__email__ = 'mvickstr@redhat.com'
__license__ = 'Apache License Version 2.0'
__version__ = '0.1'
__status__ = 'alpha'

log = logging.getLogger('rhsm-app.' + __name__)


# Exception classes used by this module.
# from later versions of subprocess, but not there on 2.4, so include our version
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


def _get_output(cmd):
    log.debug("Running '%s'" % cmd)
    process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True)
    (std_output, std_error) = process.communicate()

    log.debug("%s stdout: %s" % (cmd, std_output))
    log.debug("%s stderr: %s" % (cmd, std_error))

    output = std_output.strip()

    returncode = process.poll()
    if returncode:
        raise CalledProcessError(returncode, cmd, output=output)

    return output


def get_install_date():
    packages_with_install_date = _get_output("rpm -qa --queryformat '%{installtime:day}\n' | sort")
    list_of_packages_with_install_date = packages_with_install_date.split("\n")
    rpm_oldest_date = ''
    rpm_second_oldest_date = ''
    rpm_third_oldest_date = ''
    for package in list_of_packages_with_install_date:
        try:
            # format dates so we're looking at days only. Looking for the 3 oldest dates not times when server was updated.
            package_date = datetime(*(time.strptime(package, '%a %b %d %Y')[0:6]))
            if rpm_oldest_date is '':  # should trigger on first iteration only to populate oldest date
                rpm_oldest_date = package_date
            elif rpm_second_oldest_date is '': # should only trigger on second run
                rpm_second_oldest_date = package_date
            elif rpm_third_oldest_date is '':  # should only trigger on third run
                rpm_third_oldest_date = package_date
            elif package_date < rpm_oldest_date: # if current date is the oldest we've seen rotate all dates one spot
                rpm_third_oldest_date = rpm_second_oldest_date
                rpm_second_oldest_date = rpm_oldest_date
                rpm_oldest_date = package_date
            elif package_date < rpm_second_oldest_date and package_date != rpm_oldest_date: # if current date is second oldest push second to third
                rpm_third_oldest_date = rpm_second_oldest_date
                rpm_second_oldest_date = package_date
            elif package_date < rpm_third_oldest_date and package_date != rpm_oldest_date and package_date != rpm_second_oldest_date:
                rpm_third_oldest_date = package_date
        except ValueError:
            log.debug(str(ValueError))

    try:
        yum_first_transaction = _get_output("sudo yum history | tail -n 2")
        if 'history list' in yum_first_transaction:
            yum_first_transaction = yum_first_transaction.split("\n")[0]
        yum_date = ''
        if yum_first_transaction is not '' and '1 | ' in yum_first_transaction:
            split_string = yum_first_transaction.split("|")
            if split_string.__len__() >= 3:
                date_string = split_string[2].strip()
                if date_string.split(" ").__len__() > 1:
                    yum_date = datetime(*(time.strptime(date_string.split(" ")[0], "%Y-%m-%d")[0:6]))

        # attempt to get the root filesystem creation date.
        root_dev_output = _get_output("cat /etc/mtab | egrep ' / '")
        fs_date = ''
        if 'ext' in root_dev_output and '/dev/' in root_dev_output:
            split_string = root_dev_output.split()
            if split_string.__len__() >= 2:
                root_dev = split_string[0]
                xfs_filesystem_create_date = _get_output("sudo tune2fs -l " + root_dev + "  | grep 'Filesystem created'")
                split_string = xfs_filesystem_create_date.split("created:")
                if split_string.__len__() >= 2:
                    date_string = split_string[1].strip()
                fs_date = datetime(*(time.strptime(date_string, '%a %b  %d %H:%M:%S %Y')[0:6]))

    except ValueError:
        log.debug(str(ValueError))

    # if filesystem creation date exists and it newer than oldest package date then
    if yum_date == rpm_oldest_date or yum_date == rpm_second_oldest_date or yum_date == rpm_third_oldest_date:
        return str(yum_date)
    elif fs_date is not '':
        return str(fs_date)

# fields to collect
date = _get_output('date')
# uname_os = _get_output('uname -s ')
# uname_processor = _get_output('uname -p')
# uname_kernel = _get_output('uname -r')
# uname_all = _get_output('uname -a ')
# uname_hardware_platform = _get_output('uname -i')
linuxDistribution = _get_output('cat /etc/redhat-release').strip()
releaseNumber = "" #_get_output("cat /etc/*-release")
operatingSystemHostname = _get_output('uname -n')
try:
    physicalOrVirtual = _get_output("virt-what")
except CalledProcessError:
    log.debug(str(CalledProcessError))
    physicalOrVirtual = _get_output('')
    # TODO add check if virtual and then don't calculate CPUs
physicalSockets = _get_output("cat /proc/cpuinfo | grep  'physical id' | sort -u | wc -l")
numberofvCPUs = ""
hostedBy = ""
socketsOnHost = ""
hostClusterName = ""
numberOfHostsInCluster = ""
areRedHatPackagesInstalled = ""
numberOfRHPackagesInstalled = ""
lastInstalledRHPackage = ""
lastRHPackageInstallDate = ""
subscriptionManagerRegistered = ""
installDate = get_install_date()
authName = ""
port = ""
error = ""



print "{\"date\": \"" + date + \
      "\", \"linuxDistribution\": \"" + linuxDistribution + \
      "\",  \"releaseNumber\": \"" + releaseNumber + \
      "\",  \"operatingSystemHostname\": \"" + operatingSystemHostname + \
      "\",  \"physicalOrVirtual\": \"" + physicalOrVirtual + \
      "\",  \"physicalSockets\": \"" + physicalSockets + \
      "\",  \"numberofvCPUs\": \"" + numberofvCPUs + \
      "\",  \"hostedBy\": \"" + hostedBy + \
      "\",  \"socketsOnHost\": \"" + socketsOnHost + \
      "\",  \"hostClusterName\": \"" + hostClusterName + \
      "\",  \"numberOfHostsInCluster\": \"" + numberOfHostsInCluster + \
      "\",  \"areRedHatPackagesInstalled\": \"" + areRedHatPackagesInstalled + \
      "\",  \"numberOfRHPackagesInstalled\": \"" + numberOfRHPackagesInstalled + \
      "\",  \"lastInstalledRHPackage\": \"" + lastInstalledRHPackage + \
      "\",  \"lastRHPackageInstallDate\": \"" + lastRHPackageInstallDate + \
      "\",  \"subscriptionManagerRegistered\": \"" + subscriptionManagerRegistered + \
      "\",  \"installDate\": \"" + installDate + \
      "\",  \"authName\": \"" + authName + \
      "\",  \"port\": \"" + port + \
      "\",  \"error\": \"" + error + "\"}"
