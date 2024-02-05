#!/usr/bin/env bash

# This script is mostly based on ->
# https://github.com/Zimbra/zinstaller/blob/main/zinstaller script

# Warnings :	This script is still a WORK IN PROGRESS. Not fully tested.
#		Script to install Zimbra Classic - ONLY SINGLE NODE on a provided remote server
#
# Install scripts will be copied under known directory.
# Along with all other required files and install can be triggered
############################################################################################

function display_options {
cat << HELP_EOF
	"$0" -i <install-config> -l <license> -t <build-artifact> -a <admin-pass> --optional-pkg <pkg1> --optional-pkg <pkg2>
	options:
	-h, --help			Help
	-p, --admin-pass		Admin account password to set. (Required) (No default)
	-l, --license			License key or License file to be activated on the zimbra server. (Required) (No default)
	-i, --install-config		The default install config to configure zimbra server. (Default = $(pwd)/zim-install-config)
	-b, --build-artifact		Build artifact / Tar file path (Required) (Default = Build present in current directory)
	-n, --hostname          	Hostname for the server. (Default = $(hostname -f))
	-d, --domain-name		Domain name for zimbra installation. (Default: DOMAIN_NAME = HOSTNAME)
	-t, --time-zone			Time zone required to install. (Default: Asia/Singapore)
        --optional-pkg           	Additional package apart from default packages to install 
                                	Default: "zimbra-ldap zimbra-logger zimbra-mta zimbra-dnscache zimbra-snmp zimbra-store zimbra-apache zimbra-spell zimbra-convertd zimbra-memcached zimbra-proxy zimbra-archiving zimbra-onlyoffice zimbra-license-daemon"
					Optional pkgs: Default pkgs + zimbra-modern-ui zimbra-modern-zimlets zimbra-zimlet-document-editor zimbra-zimlet-classic-document-editor zimbra-patch zimbra-mta-patch zimbra-proxy-patch zimbra-ldap-patch
HELP_EOF
}

function main {
	set -x
	dir_script="$(cd "$(dirname "$0")" && pwd)"

	BUILD_ARTIFACT="$(find $dir_script -name "zcs-*.tgz")"
	WORK_DIR="$(ls "$BUILD_ARTIFACT" | sed s/.tgz//g)"
	INSTALL_CONFIG="$dir_script/zim-install-config"

	HOSTNAME="$(hostname -f)"
	HOST_IP="$(hostname -I | cut -f1 -d" " | tr -d '[:space:]')"
	DOMAIN_NAME="$HOSTNAME"
	ADMIN_PASS="zimbra"
	TIMEZONE="Asia/Singapore"
	CURRENT_USER="$(whoami)"
	sys_mem_kb="$(cat /proc/meminfo | grep MemAvailable | awk '{print $2}')"
	SYSTEM_MEMORY_AVAIL="$(expr $sys_mem_kb / 1024 / 1024)"
    # get version from tar file 10.0.0/8.0.0/9.0.0
	ZCS_VERSION="$(echo $BUILD_ARTIFACT | grep -oP "(?<=-)\d+(\.\d+)+")" 
	ver_pattern="10\.\([1-9]\|[1-9][0-9]\)\.*" # matches 10.1x.xx
    INSTALL_PKGS=(
        zimbra-ldap
		zimbra-logger
		zimbra-mta
		zimbra-dnscache
		zimbra-snmp
		zimbra-store
		zimbra-apache
		zimbra-spell
		zimbra-convertd
		zimbra-memcached
		zimbra-proxy
		zimbra-archiving
		zimbra-onlyoffice
		zimbra-license-daemon
    )

	redhat_release="false"
	command -v yum &>/dev/null
	if [[ "$?" -eq 0 ]]; then
		redhat_release="true";
	fi

	# Processing input
	while [ $# -gt 0 ]; do
		key="$1"
		case $key in
			-h|--help)
			display_options
			exit
			;;
			-d|--domain-name)
			DOMAIN_NAME="$2"
			shift
			shift
			;;
			-i|--install-config)
			INSTALL_CONFIG="$2"
			shift
			shift
			;;
			-b|--build-artifact)
			BUILD_ARTIFACT="$2"
			shift
			shift
			;;
			-l|--license)
			LICENSE="$2"
			shift
			shift
			;;
			-p|--admin-pass)
			ADMIN_PASS="$2"
			shift
			shift
			;;
			-t|--time-zone)
			TIMEZONE="$2"
			shift
			shift
			;;
			--optional-pkg)
			INSTALL_PKGS+=("$2")
			shift
			shift
			;;
			*)
			echo "Invalid argument(s): $2"
            echo -e "\n\n\n"
            print_help && exit 1
			;;
		esac
	done

	# Functions
	check_vars
	check_sudoer

	# Install zimbra by injecting the config values.
	install_zimbra
}


function check_vars {
	[[ -z "$INSTALL_CONFIG" ]] && echo "Install defaults file path not defined." && exit 1;

    # Check if license key of file is given, validate format
    if [[ -f "$LICENSE" ]]; then
        echo "License file is provided"
        # Check if version is 10.1x.xx
        if echo "$ZCS_VERSION" | grep $ver_pattern >> /dev/null; then
            echo "$ZCS_VERSION Does not s2upport license in file format. Use license key instead."
            exit 1;
        else 
            license_file="$LICENSE"
        fi
    else
        echo "License key is provided"
        # Check if version is 10.1x.xx
        if echo "$ZCS_VERSION" | grep $ver_pattern >> /dev/null; then
            # Check if license key is in valid format
            if echo "$LICENSE" | grep '^[0-9]\+$' >> /dev/null; then
                license_key="$LICENSE"
            else
                echo "Invalid key format: $LICENSE License key must only contain numbers."
                exit 1;
            fi
        else
            echo "$ZCS_VERSION Does not support license key. Use license xml file format."
            exit 1;
        fi
    fi

	[[ ! -f "$BUILD_ARTIFACT" ]] && echo "Cannot locate the build artifact (zcs-*.tgz) file." && exit 1;
	[[ -z "$HOSTNAME" ]] && echo "Cannot find \$HOSTNAME." && exit 1;
	[[ -z "$ADMIN_PASS " ]] && echo "Admin password is empty. Using default password." && ADMIN_PASS="zimbra"
	[[ -z "$TIMEZONE " ]] && echo "Time-zone provided is empty. Setting default Time-zone." && TIMEZONE="Asia/Singapore"
}

function check_sudoer {
	# Check if the user has sudo privilages.
	if [[ "$redhat_release" == "true" ]]; then
		if [[ -z "$(groups $CURRENT_USER | grep 'wheel')" ]]; then
			echo -e "User $CURRENT_USER does not have sudo privilages. \n
			Provide sudo privilages to $CURRENT_USER user or run as root." && exit 255;
		fi
	else
		if [[ -z "$(groups $CURRENT_USER | grep 'sudo')" ]]; then
			echo -e "User $CURRENT_USER does not have sudo privilages. \n
			Provide sudo privilages to $CURRENT_USER user or run as root." && exit 255;
		fi
	fi
	
}

function install_zimbra {
	# Uninstall existing installation if present.
	extract_build
	uninstall_zimbra

	# Prepare the server
	install_essential
	# Not mandetory on fresh servers / machines
	# disable_servs
	install_dns
	enable_ports

	# Update zimbra config file.
	update_zimbra_config

	# checkRequired function checks if the /etc/hosts file contains entry => 127.0.0.1 localhost.localdomain localhost
	# Some servers might not allow to manually edit the /etc/hosts file.
	# Commenting this function out.
	sed -i.bak 's/checkRequired/# checkRequired/' install.sh

	# Auto-install with config file.
	# Not using the install responses since they vary more often than never.
	# install.sh -l <license.xml> option is removed for 10.1.+ versions.
	if echo "$ZCS_VERSION" | grep $ver_pattern >> /dev/null; then
		sudo ./install.sh "$WORK_DIR/install.conf"
		local ret_code="$(echo $?)"
	else
		sudo ./install.sh -l "$LICENSE" "$WORK_DIR/install.conf"
		local ret_code="$(echo $?)"
	fi
	
	if [[ "$ret_code" -eq 0 ]]; then
		echo "Zimbra installation and setup completed."
		echo "Activating License"
		sudo su - zimbra -c "zmlicense -a"
		[[ "$?" -ne "0" ]] && echo "License activation failed. Please check the logs."
		echo "Running post-install configuration and checks."
		
		# Run post install config and print information.
		postinstall && print_install_complete
	else
		echo "Error: installation failed." && exit 1
	fi
}

function extract_build {
	# Extract build artifact.
	echo "Extracting the build artifact..."
	tar -xzvf "$BUILD_ARTIFACT"
	[[ "$?" -ne "0" ]] && echo "Cannot extract the build artifact." && exit 1;
}

function uninstall_zimbra {
	# Uninstall existing installation if present.
	cd "$WORK_DIR" && echo "Checking if zimbra is already installed"
	sudo su - zimbra -c 'zmcontrol -v'
	if [[ $? -eq 0 ]]; then
		echo "Warning: $HOSTNAME has following version of zimbra already installed -"
		sudo su - zimbra -c 'zmcontrol -v'
	else
		echo "Already installed zimbra version not found"
	fi
	echo "Preparing to uninstall irrespective of zimbra is installed or not. \n
			This will clear the /opt/zimbra and other settings if present."
	# 'yes' answers to the confirm uninstallation question if asked.
	sudo ./install.sh -u << 'EOF' 
	Yes
EOF
	zimbra_dir="/opt/zimbra"
	echo " Checking if the zimbra is uninstalled properly..."
	if [[ -d "$zimbra_dir" ]]; then
		command -v zmcontrol >> /dev/null
		if [[ "$?" -ne 0 ]]; then
			echo -e "Warning: The 'zmcontrol' command and directory still \"$zimbra_dir\" still exists.\n
					Zimbra might not be completely uninstalled.\n This could affect the new installation."
		fi
		echo "Zimbra Uninstall is successful."
	fi
}

function disable_servs {
	# Disable all non essential services for installing zimbra.
	echo "Disabling some of the non-essential services for Zimbra ..."
	services_arr=(
		postfix httpd exim named apache2 sendmail mysqld mariadb
	)

	# Disable services one by one.
	for i in ${services_arr[@]}; do
		echo "Processing service $i"
		sudo systemctl stop "$i" || echo "Warning: Cannot stop the service $i. Installation may get affected."
		sudo systemctl disable "$i" || echo "Warning: Cannot Disable the service $i. Installation may get affected."
		sudo systemctl mask "$i" || echo "Warning: Cannot Mask the service $i. Installation may get affected."
	done
}

function install_essential {
	echo "Updating system and installing some essential packages ..."

	if [[ "$redhat_release" == "true" ]]; then
		sudo yum update -q -y < /dev/null > /dev/null
		sudo yum upgrade -q -y < /dev/null > /dev/null
	else
		sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq -y < /dev/null > /dev/null
		sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -qq -y < /dev/null > /dev/null
	fi

	list_essentials_ubuntu=(
		apt-utils netcat-openbsd sudo libidn11 libpcre3 libgmp10 \
		libexpat1 libstdc++6 libaio1 resolvconf \
		unzip pax sysstat sqlite3 dnsmasq lsb-release net-tools \
		netfilter-persistent dnsutils iptables sed wget rsyslog ldapscripts
	)
	list_essentials_redhat=(
		netcat-openbsd sudo libidn11 libpcre3 libgmp10 \
		libexpat1 libstdc++6 libaio1 resolvconf \
		unzip pax sysstat sqlite3 dnsmasq lsb-release net-tools \
		netfilter-persistent dnsutils iptables sed wget rsyslog ldapscripts
	)

	# Prints all package names in a single line to trigger install.
	all_pkgs_ubuntu="$(echo ${list_essentials_ubuntu[*]})"
	all_pkgs_redhat="$(echo ${list_essentials_redhat[*]})"
	if [[ "$redhat_release" == "true" ]]; then
		sudo yum install -q -y $all_pkgs_redhat< /dev/null > /dev/null
	else
		sudo DEBIAN_FRONTEND=noninteractive apt-get install -qq -y $all_pkgs_ubuntu< /dev/null > /dev/null
	fi
	[[ "$?" -ne "0" ]] && echo "Cannot get some of essential packages. Installation may fail." || \
	echo "Essential packages installed successfully."
}

function install_dns {
	# Install a DNS Server
	echo "Configuring dnsmasq ..."
	sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.old || true

	#create the conf file
	sudo echo -e "server=8.8.8.8\nserver=8.8.4.4\nserver=9.9.9.9\nserver=149.112.112.112\nserver=1.1.1.1\nserver=1.0.0.1\nlisten-address=127.0.0.1\ndomain='$DOMAIN_NAME'\nmx-host='$DOMAIN_NAME','$HOSTNAME',0\naddress=/'$HOSTNAME'/'$MYIP'\n" \
	>> /etc/dnsmasq.conf
	local resolv_file="/etc/resolv.conf"
	grep 'nameserver 8.8.8.8' /etc/resolv.conf >> /dev/null
	local ret="$(echo $?)"
	if [[ "$ret" -eq 0 ]]; then
		echo "Nameserver is correct in $resolv_file"
    else
		# Edit resolve.conf
		sudo cp /etc/resolv.conf /etc/resolv.conf.old
        sudo sed -i 's/^nameserver [0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/nameserver 8.8.8.8/' "$resolv_file"
        echo "Replacement completed!"
    fi

	# restart dns services
	sudo systemctl enable dnsmasq.service > /dev/null 2>&1 \
	&& sudo systemctl restart dnsmasq.service
	if [[ "$?" -eq 0 ]]; then
		echo "dnsmasq.service started successfully."
	else
		echo "Failed to start service -> dnsmasq.service" && exit 1;
	fi

	# Check DNS
	echo "Checking DNS ..."
	name="$(host license.zimbra.com)"
	if [[ "$name" == *"not found"* ]]; then
		echo -e "DNS resolution failed! Check your resolve.conf file." && exit 1
	else
		echo -e "DNS resolution done."
	fi
}

function enable_ports {
	# Enable all required ports using iptables.
	echo "Enabling firewall for Zimbra ports ..."
	echo "Ports 22 / 25 / 143 / 80 / 443 / 465 / 587 / 995 / 993 / 9071 will be opened to the internet."
	echo "Please check your iptables for more info."

	# Array of all ports required.
	ports_arr=("25" "80" "110" "143" "443" "465" "587" "993" "995" "7071" "9071")

	echo "Opening the ports with iptables..."
	for port in ${ports_arr}; do
		echo -e "Allowing incoming traffic on port $port ...\n"
		sudo iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
	done

	#Allow ports
	for p in ${ports_arr[@]}; do
		sudo lsof -i tcp:"$p"
		if [[ "$?" -eq 0 ]]; then
			# Kill all proccesses on that port using PID's
			sudo kill "$(sudo lsof -t -i tcp:"$p")"
			# Alternate option - permissions not propagated towards the end of the pipeline.
			# sudo lsof -i tcp:"$p" | awk 'NR!=1 {print $2}' | xargs sudo kill
			echo "Killed all processes on Port $p for installation."
		else
			echo "Warning: Failed to Kill all processes on Port $p"
			echo "Port conflicts may occur."
		fi
	done

	#Check Firewall -- Commented out for testing purposes.
	# response=$(curl --write-out '%{http_code}' --silent --output /dev/null https://license.zimbra.com)
	# if [[ "$response" == "200" ]]; then
	# 	echo "Zimbra servers reachable ..."
	# else
	# 	echo "Issue with firewall ... Please check." && exit 1
	# fi
}

function update_zimbra_config {
	# Edit zimbra config files to inject and trigger automated install
	sed -e "s|placeholder_hostname|$HOSTNAME|g" \
		-e "s|placeholder_hostip|$HOST_IP|g" \
		-e "s|placeholder_domainname|$DOMAIN_NAME|g" \
		-e "s|placeholder_adminpass|$ADMIN_PASS|g" \
		-e "s|placeholder_timezone|$TIMEZONE|g" \
		-e "s|placeholder_systemmem|$SYSTEM_MEMORY_AVAIL|g" $INSTALL_CONFIG >> $WORK_DIR/install.conf
	# Add Pkgs to install
	install_pkgs_string="$(echo ${INSTALL_PKGS[*]})"
	sed -e "s|placeholder_install_pkgs|$install_pkgs_string|g" $INSTALL_CONFIG >> $WORK_DIR/install.conf
	# Add License key if version => 10.1x.xx
	if echo "$ZCS_VERSION" | grep $ver_pattern >> /dev/null; then
		echo "NOTE: Activate license after installation is selected by default for $ZCS_VERSION"
		echo "LICENSEACTIVATIONOPTION=1" >> $WORK_DIR/install.conf
		echo "LICENSEKEY=$license_key" >> $WORK_DIR/install.conf
	fi
}

function postinstall {
	# Checks LICENSE and service status
	echo "Running post installation checks and settings..."
	echo "Adding Admin console proxy" && \
	sudo su - zimbra -c "zmcontrol -v" || exit 1;
	sudo su - zimbra -c "/opt/zimbra/libexec/zmproxyconfig -e -w -C -H $HOSTNAME"
	local status="$(sudo su - zimbra -c "zmcontrol status")"
	if [[ $status == 'not running' ]]; then
		echo "Error: Some services are not running. Please check logs." && exit 1
	else
		echo "All services are up and running. ZCS auto installation is complete."
		echo "Check the service status on $HOSTNAME "
		do_settings
	fi
}

function do_settings {
	# Do Optimal security settings
	# Enable admin proxy
	# Update Authkeys and Syslog
}

function print_install_complete {
	# Info about new installation
	cat << here
	Your new Zimbra installation details are:
	- Webmail Login:	https://${HOSTNAME}
	- Admin Console:	https://${HOSTNAME}:7071
	- Admin Username:	admin@${HOSTNAME}
	- Admin Password:	$ADMIN_PASS
here
}

# #########################
	main "$@"
# #########################
