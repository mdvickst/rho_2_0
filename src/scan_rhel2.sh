#!/usr/bin/env bash

function get_install_date
    {
    return_string='"package_list":['
    first_package="true"
    while read -r line ; do
        if [[ "$first_package" -eq "true" ]]; then
            echo "first String"
            return_string+="\"$line\""
            first_package="false"
        else
            return_string+=", \"$line\""
        fi
    done < <(rpm -qa --qf '%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|%{BUILDTIME}|%{BUILDHOST}|%{SOURCERPM}|%{PACKAGER}|%{INSTALLTIME:date}|%{BUILDTIME:date}\n'  2> /dev/null)

    return_string+="]"
    first_yum_transaction=""
    while read -r line ; do
        if [[ ${line} != *'history list'* ]]; then
            first_yum_transaction=", \"yum_history\":\"$line\""
        fi
    done < <(sudo yum history | tail -n 2 2> /dev/null)
    return_string+="$first_yum_transaction"

    # attempt to get the root filesystem creation date.
    root_dev_output=$("cat /etc/mtab | egrep ' / ' 2> /dev/null")
    fs_date=''
    if [[ root_dev_output == *'ext'* && root_dev_output == *'/dev/'* ]]; then
        IFS=' ' read -r -a split_string <<< "$root_dev_output"
        if [[ ${#split_string[@]} -ge 3 ]]; then
            root_dev=split_string[0]
            ext_filesystem_create_date=$("sudo tune2fs -l " + root_dev + "  | grep 'Filesystem created'  2> /dev/null")
            return_string+=", \"ext_filesystem_create_date\": \"$ext_filesystem_create_date\""
            echo "$ext_filesystem_create_date"
        fi
    fi
    }

source $1

if [ -z "$state" ]; then
    printf '{"failed": true, "msg": "missing required arguments: state"}'
    exit 1
fi

changed="false"
msg=""
return_string=""

get_install_date

printf '{"changed": %s, "msg": "%s", %s}' "$changed" "$msg" "$return_string"

