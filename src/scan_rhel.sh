#!/usr/bin/env bash

function get_install_date
    {
    packages_with_install_date=$(rpm -qa --queryformat '%{installtime:day}\n' | sort)
    IFS='\n' read -r -a list_of_packages_with_install_date <<< "$packages_with_install_date"
    rpm_oldest_date=''
    rpm_second_oldest_date=''
    rpm_third_oldest_date=''
    for package in ${list_of_packages_with_install_date[@]}; do
            # format dates so we're looking at days only. Looking for the 3 oldest dates not times when server was updated.
            package_date=$(date -d "$package %Y%m%d")
            if [[ -z rpm_oldest_date ]]; then  # should trigger on first iteration only to populate oldest date
                rpm_oldest_date=$package_date
            elif [[ -z rpm_second_oldest_date ]]; then  # should only trigger on second run
                rpm_second_oldest_date=$package_date
            elif [[ -z rpm_third_oldest_date ]]; then  # should only trigger on third run
                rpm_third_oldest_date=$package_date
            elif [[ package_date -lt rpm_oldest_date ]]; then # if current date is the oldest we've seen rotate all dates one spot
                rpm_third_oldest_date=rpm_second_oldest_date
                rpm_second_oldest_date=rpm_oldest_date
                rpm_oldest_date=package_date
            elif [[ package_date -lt rpm_second_oldest_date && package_date != rpm_oldest_date ]]; then # if current date is second oldest push second to third
                rpm_third_oldest_date=rpm_second_oldest_date
                rpm_second_oldest_date=package_date
            elif [[ package_date -lt rpm_third_oldest_date && package_date != rpm_oldest_date && package_date != rpm_second_oldest_date ]]; then
                rpm_third_oldest_date=package_date
            fi
    done
    yum_first_transaction=$(sudo yum history | tail -n 2)
    if [[ yum_first_transaction == *'history list' * ]]; then
        IFS='\n' read -r -a yum_first_transaction_list <<< "$yum_first_transaction"
        yum_first_transaction=${yum_first_transaction_list[0]}
    fi
    yum_date=''
    if [[ -n yum_first_transaction && yum_first_transaction == *'1 | '* ]]; then
        IFS='|' read -r -a yum_first_transaction_list <<< "$yum_first_transaction"
        if [[ ${#yum_first_transaction_list[@]} -ge 3 ]]; then
            date_string=${yum_first_transaction_list[2]}
            date_string_no_whitespace="$(echo -e "${date_string}" | tr -d '[[:space:]]')"

            if date_string.split(" ").__len__() > 1:
                yum_date=datetime(*(time.strptime(date_string.split(" ")[0], "%Y-%m-%d")[0:6]))
        fi

    # attempt to get the root filesystem creation date.
    root_dev_output=$("cat /etc/mtab | egrep ' / '")
    fs_date=''
    if 'ext' in root_dev_output and '/dev/' in root_dev_output:
        split_string=root_dev_output.split()
        if split_string.__len__() >= 2:
            root_dev=split_string[0]
            xfs_filesystem_create_date=$("sudo tune2fs -l " + root_dev + "  | grep 'Filesystem created'")
            split_string=xfs_filesystem_create_date.split("created:")
            if split_string.__len__() >= 2:
                date_string=split_string[1].strip()
            fs_date=datetime(*(time.strptime(date_string, '%a %b  %d %H:%M:%S %Y')[0:6]))


function create_file
    {
    if [ -f "$dest" ]; then
        changed="false"
        msg="file already exists"
    else
        echo 'Hello, "world!"' >> $dest
        changed="true"
        msg="file created"
    fi
    contents=$(cat "$dest" 2>&1 | python -c 'import json,sys; print json.dumps(sys.stdin.read())')
    }

source $1

if [ -z "$state" ]; then
    printf '{"failed": true, "msg": "missing required arguments: state"}'
    exit 1
fi

changed="false"
msg=""
contents=""



printf '{"changed": %s, "msg": "%s", "contents": %s}' "$changed" "$msg" "$contents"

exit 0