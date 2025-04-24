#!/bin/bash

script_name="ngenius_config_restore.sh"
restore_log="/tmp/ngenius_config_restore.log"
version="10-10-2024"

backup_partition_candidates=(/metadata)
backup_partition=""
backup_directory="backup"
backup_path=""

verbose_mode=0

restore_list=(/opt/NetScout /opt/platform/.store /root/.ssh /var/adm/NetScout /etc/hostname /etc/hosts /etc/localtime /data /etc/udev/rules.d/25-names.rules)
restore_list_geo=(/iris /iris_kpi_db)

group_list=(ngenius consoleplus)
group_list_geo=(iris geo)

user_list=(ngenius)
user_list_geo=(iris geo)

partition_list=(/asi /nsSwap- /metadata /xdr)
partition_list_geo=(/archive)

# Exit immediately on Ctrl-C
trap "echo 'Exiting'; exit 1" SIGINT

log() {
	echo "$*" >> $restore_log
	if [ $verbose_mode = 1 ]; then
		echo "$*"
	fi
}

log_and_print() {
	echo "$*" | tee -a $restore_log
}

warning() {
	log_and_print "Warning: $*"
}

error() {
	echo "Error: $*" | tee -a $restore_log >&2
	echo "Check the log for details $restore_log" | tee -a $restore_log >&2
	exit 1
}

find_backup_partition() {
	log "--- In function: find_backup_partition"

	for partition in "${backup_partition_candidates[@]}"; do

		# Check if partition exists
		partition_exists=$(lsblk -no label | grep -c "$partition")
		if [ $partition_exists = 0 ]; then
			log "Partition $partition not found, skipping"
			continue
		fi

		# Create mount point and mount
		partition_is_mounted=$(lsblk -o mountpoint | grep -c "$partition")
		if [ $partition_is_mounted = 0 ]; then
			log "Partition $partition not mounted"
			if [ ! -d "$partition" ]; then
				log "Creating mount point $partition"
				mkdir -p "$partition" &>> $restore_log
			fi
			log "Mounting partition $partition to $partition"
			mount LABEL="$partition" "$partition" &>> $restore_log
			if [ $? -ne 0 ]; then
				log "Failed to mount partition $partition to $partition, skipping"
				continue
			fi
		fi

		# Check for backup directory
		backup_path="$partition/$backup_directory"
		if [ ! -d "$backup_path" ]; then
			log "No backup found at $backup_path, skipping"
			continue
		fi

		backup_partition="$partition"
		log "Found backup partition $backup_partition"
		break
	done

	if [ -z "$backup_partition" ]; then
		error "Failed to find backup partition"
	fi
}

# Lots of checks because important
restore_fstab_entries() {
	log "--- In function: restore_fstab_entries"

	if [ ! -f "$backup_path/etc/fstab" ]; then
		error "Missing $backup_path/etc/fstab"
	fi

	fstab=/tmp/fstab
	fstab_backup=/tmp/fstab.backup

	log "Copying /etc/fstab to $fstab"
	rsync -a /etc/fstab $fstab &>> $restore_log
	if [ $? -ne 0 ]; then
		error "Failed to copy /etc/fstab to $fstab"
	fi

	log "Copying $backup_path/etc/fstab to $fstab_backup"
	rsync -a "$backup_path/etc/fstab" "$fstab_backup" &>> $restore_log
	if [ $? -ne 0 ]; then
		error "Failed to copy $backup_path/etc/fstab to $fstab_backup"
	fi

	for label in "${partition_list[@]}"; do

		log "$label: Checking $fstab_backup for backed up partition entry"
		if ! grep -q "$label" "$fstab_backup"; then
			log "$label: Not found, skipping"
			continue
		fi
		
		if grep -q "$label" "$fstab"; then
			log "$label: Already in $fstab, skipping"
			continue
		fi

		log "$label: Found, saving to $fstab"
		grep "$label" "$fstab_backup" >> "$fstab"
		if [ $? -ne 0 ]; then
			warning "$label: Failed to save partition entry to $fstab"
		fi
	done

	log "Creating backup of /etc/fstab to /etc/fstab.bak before overwriting"
	rsync -a /etc/fstab /etc/fstab.bak &>> $restore_log
	if [ $? -ne 0 ]; then
		error "Failed to create backup of /etc/fstab"
	fi

	log "Checking that $fstab is populated before overwriting /etc/fstab"
	fstab_uuid_entries=$(grep -c "^UUID=" $fstab)
	if [ $fstab_uuid_entries -lt 4 ]; then
		error "$fstab does not have enough entries"
	fi	

	fstab_storage_entries=$(grep -c "^LABEL=" $fstab)
	if [ $fstab_storage_entries -lt 3 ]; then
		error "$fstab missing storage partitions"
	fi	

	log "Overwritng /etc/fstab with $fstab"
	rsync -a "$fstab" /etc/fstab &>> $restore_log
	if [ $? -ne 0 ]; then
		error "Failed to move $fstab to /etc/fstab, restore /etc/fstab from /etc/fstab.bak if necessary"
	fi
}


check_backup_log() {
	log "--- In function: check_backup_log"

	backup_log="$backup_path/ngenius_config_backup.log"
	if [ ! -e "$backup_path" ]; then
		error "Failed to find backup log"
	fi

	if grep -q "Detected Geo" "$backup_log"; then
		log "Detected Geo"
		# Add geo files to restore lists
		partition_list+=("${partition_list_geo[@]}")
		group_list+=("${group_list_geo[@]}")
		user_list+=("${user_list_geo[@]}")
		restore_list+=("${restore_list_geo[@]}")

		# Recreate /sr2d directory
		sr2d="/sr2d"
		if [ ! -d "$sr2d" ]; then
			log "Creating directory $sr2d"
			mkdir "$sr2d" &>> $restore_log
			if [ $? -ne 0 ]; then
				error "Failed to create directory $sr2d"
			fi
		fi
	fi

	pfx="/opt/platform/.pfx_enable"
	if grep -q "Detected Packet Flow eXtender (PFX)" "$backup_log"; then
		log "Detected Packet Flow eXtender (PFX)"
		restore_list+=("$pfx")
	fi
}

restore_mount_points() {
	log "--- In function: restore_mount_points"

	for mount_point in $(grep ^LABEL= /etc/fstab | awk '{print $2}' | grep ^/); do
		if [ -e "$mount_point" ]; then
			log "Mount point $mount_point already exists, skipping"
			continue
		fi
		log "Creating mount point $mount_point"
		mkdir "$mount_point" &>> $restore_log
		if [ $? -ne 0 ]; then
			warning "Failed to create mount point $mount_point"
		fi
	done	
}

restore_groups_and_users() {
	log "--- In function: restore_groups_and_users"

	for group in "${group_list[@]}"; do
		if getent group "$group" &> /dev/null; then
			log "Group $group already created, skipping"
			continue
		fi
		gid=$(grep ^$group $backup_path/etc/group | awk -F':' '{print $3}')
		if [ -z $gid ]; then
			warning "gid for group $group not found, skipping"
			continue
		fi
		log "Restoring group $group with gid $gid"
		groupadd -g $gid $group &>> $restore_log
		if [ $? -ne 0 ]; then
			warning "Failed to add group $group with gid $gid"
		fi
	done

	for user in "${user_list[@]}"; do
		if getent passwd "$user" &> /dev/null; then
			log "User $user already created, skipping"
			continue
		fi
		uid=$(grep ^$user $backup_path/etc/passwd | awk -F':' '{print $3}')
		if [ -z $uid ]; then
			warning "uid for user $user not found, skipping"
			continue
		fi
		log "Restoring user $user with uid $uid"
		case $user in
			"ngenius")
				useradd -u $uid -g ngenius -d /opt/NetScout -s /bin/bash ngenius &>> $restore_log
				[ $? -ne 0 ] && warning "Failed to create user $user"
			;;
			"iris")
				useradd -u $uid -g iris -d /iris/home -s /bin/bash iris &>> $restore_log
				[ $? -ne 0 ] && warning "Failed to create user $user"
				usermod -aG ngenius iris &>> $restore_log
				[ $? -ne 0 ] && warning "Failed to add user $user to group ngenius"
			;;
			"geo")
				useradd -u $uid -g geo -d /iris/geo -s /bin/bash geo &>> $restore_log
				[ $? -ne 0 ] && warning "Failed to create user $user"
				usermod -aG ngenius geo &>> $restore_log
				[ $? -ne 0 ] && warning "Failed to add user $user to group ngenius"
			;;
		esac
	done
}

# Give warning for files missing from backup
# Give error for failed restores
restore_files() {
	log "--- In function: restore_files"
	log_and_print "Restoring backup"

	for file in "${restore_list[@]}"; do
		file_backup="$backup_path/$file"

		if [ ! -e "$file_backup" ] && [ ! -L "$file_backup" ]; then
			warning "Failed to restore $file: not in backup"
			continue
		fi

		# If symlink
		if [ -L "$file_backup" ]; then
			log "Restoring symlink $file"
			# If file already exists as a non-symlink, move it out of the way
			if [ -e "$file" ] && [ ! -L "$file" ]; then
				log "Moving original non-symlink $file to /tmp"
				mv -f "$file" "/tmp/$file" &>> $restore_log
			fi
			rsync -a "$file_backup" "$file" &>> $restore_log
			if [ $? -ne 0 ] || [ ! -L "$file" ]; then
				error "Failed to restore symlink $file"
			fi
			continue
		fi

		# If directory
		if [ -d "$file_backup" ]; then
			log "Restoring directory $file"
			rsync -a "$file_backup/" "$file" &>> $restore_log
			if [ $? -ne 0 ] || [ ! -d "$file" ]; then
				error "Failed to restore directory $file"
			fi
			continue
		fi

		# If file
		if [ -f "$file_backup" ]; then
			log "Restoring file $file"
			rsync -a "$file_backup" "$file" &>> $restore_log
			if [ $? -ne 0 ] || [ ! -f "$file" ]; then
				error "Failed to restore file $file"
			fi
			continue
		fi

		warning "Failed to restore $file: unknown file type"
	done
}

check_restore() {
	log "--- In function: check_restore"

	if [ -e /opt/NetScout/rtm/bin/stop1 ] && grep -qv "export PERFMGR_PATH; exit" /opt/NetScout/rtm/bin/stop1; then
		log "Adding 'exit' to /opt/NetScout/rtm/bin/stop1"
		sed -i "s/export PERFMGR_PATH/export PERFMGR_PATH; exit/" /opt/NetScout/rtm/bin/stop1 &>> $restore_log
	fi

	log "Checking partition_install.xml"
	partition_install="/opt/platform/.store/partition_install.xml"
	if [ ! -e "$partition_install" ]; then
		error "$partition_install not found, stop and contact support"
	fi
	if [ $(wc -l "$partition_install" | awk '{print $1}') -lt 5 ]; then
		error "$partition_install too small, stop and contact support"
	fi
	cat "$partition_install" >> $restore_log
	echo "" >> $restore_log

	log "Checking /etc/fstab"
	fstab="/etc/fstab"
	if [ ! -e "$fstab" ]; then
		error "$fstab not found, stop and contact support"
	fi
	if [ $(grep -c "^LABEL=" "$fstab") -lt 3 ]; then
		error "$fstab missing storage partition entries, stop and contact support"
	fi
	cat "$fstab" >> $restore_log
}

restore_root_password() {
	log "--- In function: restore_root_password"
	
	shadow="$backup_path/etc/shadow"
	previous_root_password=$(grep -E "^root:" "$shadow" | cut -d: -f2)
	if [ -z "$previous_root_password" ]; then
		warning "Failed to restore previous root password: not found"
		return 1
	fi

	shadow_backup="/etc/shadow.bak"
	log "Creating backup $shadow_backup"
	rsync -a $shadow $shadow_backup &>> $restore_log
	if [ $? -ne 0 ]; then
		warning "Failed to restore previous root password: failed to create backup $shadow_backup"
		return 1
	fi

	shadow_temp="/tmp/shadow"
	log "Recreating /etc/shadow at $shadow_temp but with previous root password"
	awk -F: -v OFS=: -v password="$previous_root_password" '{ if ($1 == "root") $2 = password; print }' /etc/shadow > $shadow_temp 2>> $restore_log
	chmod $(stat -c "%a" /etc/shadow) /tmp/shadow

	log "Overwriting /etc/shadow with $shadow_temp"
	rsync -a $shadow_temp /etc/shadow 
	if [ $? -ne 0 ]; then
		warning "Failed to restore previous root password: failed to replace /etc/shadow with $shadow_temp"
		return 1
	fi

	log "Restored previous root password"
}

restore_ntp() {
	log "--- In function: restore_ntp"

	# Restore ntp/linuxptp
	chrony_conf="/etc/chrony.conf"
	if [ -e "$backup_path/etc/ntp.conf" ]; then
		# restore from ntpd on CentOS to chronyd on Oracle
		num_of_ntp=$(cat $backup_path/etc/ntp.conf | grep server | wc -l)
		> $chrony_conf
		while [ $num_of_ntp -gt 0 ]; do
			cat << EOF >> $chrony_conf
$(cat $backup_path/etc/ntp.conf | grep -m $num_of_ntp server | tail -n 1)
sourcedir /run/chrony-dhcp
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
keyfile /etc/chrony.keys
ntsdumpdir /var/lib/chrony
leapsectz right/UTC
logdir /var/log/chrony
log measurements statistics tracking
EOF
			((num_of_ntp--))
		done
		# general changes for chronyd
		chmod 750 /var/log/chrony			&> /dev/null
		chmod 777 /var/log				&> /dev/null
		sed -i '3i \rotate 7' /etc/logrotate.d/chrony	&> /dev/null
		systemctl enable chronyd.service		&> /dev/null
		/opt/platform/linuxptp/disable_linuxptp.sh 1	&> /dev/null
		/opt/NetScout/rtm/bin/disable_ptpv2.sh		&> /dev/null
		chkconfig ptpd off				&> /dev/null
	elif [ -e "$backup_path/etc/chrony.conf" ]; then
		# restore from chronyd on Oracle to chronyd on Oracle
		cp $backup_path/etc/chrony.conf $chrony_conf	&> /dev/null
		# general changes for chronyd
		chmod 750 /var/log/chrony			&> /dev/null
		chmod 777 /var/log				&> /dev/null
		sed -i '3i \rotate 7' /etc/logrotate.d/chrony	&> /dev/null
		systemctl enable chronyd.service		&> /dev/null

		/opt/platform/linuxptp/disable_linuxptp.sh 1	&> /dev/null
		/opt/NetScout/rtm/bin/disable_ptpv2.sh		&> /dev/null
		chkconfig ptpd off				&> /dev/null
	else
		# it was not using ntpd/chronyd before
		# switch to linuxptp
		# One case: customer was using linuxptp
		# Second case: customer was using ptpv2, need to restore /opt/platform/ptpv2
		# If /opt/platform/linuxptp exists, backup and restore it
		# If /opt/platform/ptpv2 exists, backup and restore it
		systemctl disable ntpd.service								&>/dev/null
		systemctl disable chronyd								&>/dev/null
		if [ -e $backup_path/opt/platform/linuxptp/linuxptp.modules ]; then
			cp $backup_path/opt/platform/linuxptp/linuxptp.modules /etc/sysconfig/modules/	&>/dev/null
		fi
		cp $backup_path/opt/platform/linuxptp/ptp4l.service /etc/systemd/system/		&>/dev/null
		cp $backup_path/opt/platform/linuxptp/phc2sys.service /etc/systemd/system/		&>/dev/null
		cp $backup_path/opt/platform/linuxptp/linuxptp.service /etc/systemd/system/		&>/dev/null
		systemctl --system daemon-reload							&>/dev/null
		systemctl enable linuxptp.service ptp4l.service phc2sys.service				&>/dev/null
		systemctl disable ntpd.service								&>/dev/null
		systemctl stop ntpd.service								&>/dev/null
		service ptpv2d stop									&>/dev/null
		chkconfig ptpv2d off									&>/dev/null
		ptp_port=$(grep 319 /etc/sysconfig/iptables)
		if [ -z "$ptp_port" ]; then
			iptables-save > /etc/sysconfig/iptable.save					&>/dev/null
			iptables -D  INPUT -j REJECT --reject-with icmp-host-prohibited			&>/dev/null
			iptables -A INPUT -p udp -m state --state NEW -m udp --dport 319 -j ACCEPT	&>/dev/null
			iptables -A INPUT -p udp -m state --state NEW -m udp --dport 320 -j ACCEPT	&>/dev/null
			iptables -A  INPUT -j REJECT --reject-with icmp-host-prohibited			&>/dev/null
			iptables-save > /etc/sysconfig/iptables						&>/dev/null
		fi
		if [ -e $backup_path/opt/platform/linuxptp/lxptp.logrotate ]; then
			cp $backup_path/opt/platform/linuxptp/lxptp.logrotate /etc/logrotate.d/lxptp	&>/dev/null
		fi
	fi
}

copy_log_to_backup() {
	log "--- In function: copy_log_to_backup"

	log "Copying log to $backup_path"
	rsync -a "$restore_log" "$backup_path" &> /dev/null
	if [ $? -ne 0 ]; then
		error "Failed to copy log"
	fi

	log_and_print "Success"
}

print_log_header() {
	log_and_print "$script_name version $version"

	# Instead of overwriting previous log, move to /tmp
	if [ -f $restore_log ]; then
		restore_log_backup=$(mktemp)
		mv $restore_log $restore_log_backup
	fi

	cat << EOF > $restore_log
********************************************
Running: $script_name $*
Version: $version
Install date: $(date)
********************************************

EOF
}

usage() {
	cat <<EOF
$script_name version $version

$script_name restores the backup of files to maintain InfiniStream's storage
partitions across OS upgrades and reimages.

Usage: $script_name [OPTIONS]
    -v | --version    Print script version
    -d | --verbose    Enable verbose mode
    -h | --help       Show this usage info

EOF
	exit $1
}

parse_arguments() {
	while true; do
		case "$1" in
			-v | --version)
				echo "$script_name version $version"
				exit 0 ;;
			-d | --verbose)
				verbose_mode=1
				shift ;;
			-h | --help)
				usage 0 ;;
			"")
				break ;;
			*)
				usage 1 ;;
		esac
	done
}

# Restore /dev/nsa symlinks to storage partitions
# Only give warning on error because InfiniStream still works without them
restore_dev_nsa() {
	log "--- In function: restore_dev_nsa"

	# Create scsi_id symlink
	link="/sbin/scsi_id"
	target="/lib/udev/scsi_id"
	if [ ! -e "$link" ] && [ ! -L "$link" ] && [ -f "$target" ]; then
		log "Creating symlink $link to $target"
		ln -s "$target" "$link" &>> $restore_log
		if [ $? -ne 0 ]; then
			warning "Failed to restore /dev/nsa symlinks: Failed to create symlink"
			return 1
		fi
	fi

	udev_rules="/etc/udev/rules.d/25-names.rules"
	if [ ! -f "$udev_rules" ]; then
		warning "Failed to restore /dev/nsa symlinks: $udev_rules doesn't exist"
		return 1
	fi

	# Perform rough check for if file is empty (less than 5 characters)
	if [ $(wc -c "$udev_rules" | awk '{print $1}') -lt 5 ]; then
		warning "Failed to restore /dev/nsa symlinks: $udev_rules is empty"
		return 1
	fi

	log "Triggering udev events for block devices to create /dev/nsa* symlinks"
	udevadm trigger --subsystem-match=block &>> $restore_log
	if [ $? -ne 0 ]; then
		warning "Failed to restore /dev/nsa symlinks: Failed to trigger udev events for block devices"
		return 1
	fi

	log "Waiting for udev events to be processed"
	udevadm settle &>> $restore_log
	if [ $? -ne 0 ]; then
		warning "Failed to restore /dev/nsa symlinks: Failed to process udev events"
		return 1
	fi

	if ! ls /dev/nsa* &> /dev/null; then
		warning "Failed to restore /dev/nsa symlinks: Symlinks weren't created"
		return 1
	fi
}

parse_arguments $*
print_log_header $*
find_backup_partition
check_backup_log
restore_fstab_entries
restore_mount_points
restore_groups_and_users
restore_files
restore_dev_nsa
restore_root_password
restore_ntp
check_restore
copy_log_to_backup
