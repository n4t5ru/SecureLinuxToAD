#!/bin/bash
: '
    Author:         n4t5ru
    Email:          hello@nasru.me
    Version:        1.0
    Created:        11/DEC/2022
    ScriptName:     SecureLinuxToAD-Debian
    Description:    Automated the steps taken to enroll Debian Servers to Active Directory Environment and harden the linux
    How To:         Run the script as Root
'
# Colour output definitions
red=$( tput setaf 1 );
yellow=$( tput setaf 3 );
green=$( tput setaf 2 );
normal=$( tput sgr 0 );

# Global Variables
Supressor=$(> /dev/null 2>&1);
UIDCheck=$(awk -F: '($3 == "0") {print}' /etc/passwd);

printf "$red\nWelcome to SecureLinuxToAD - Debian\n"
printf "This script is automated steps to enroll Debian Servers to Active Directory Environment and harden the linux.\n1) Just Enroll to AD\n2)Just Harden Linux\n3) Do Both"
echo "Your Option:"
read Options

case $Options in
1)
    LinuxToAD()
;;
2)
    linuxHardening()
;;
3)
    LinuxToAD()
    linuxHardening()
;;
*)
    echo "Stick to the given options..."
;;
esac

function LinuxToAD() {

echo 'Enter your domain Name:'
read domainName
echo 'Enter your Hostname Name:'
read hostName
echo 'Enter Domain Admin User'
read domainAdmin

echo 'You will be prompted to enter domain admin password in a bit....'

#change hostname to user preference
hostnamectl set-hostname $hostName.$domainName

#install the initial required tools
apt-get install -y realmd libnss-sss libpam-sss sssd sssd-tools adcli samba-common-bin oddjob oddjob-mkhomedir packagekit $Supressor

#join the doiman
realm join -v -U $domanAdmin $domainName

cat <<EOF >> /usr/share/pam-configs/mkhomedir 
Name: activate mkhomedir
Default: yes
Priority: 900
Session-Type: Additional
Session: required   
pam_mkhomedir.so umask=0022 skel=/etc/skel
EOF

pam-auth-update

systemctl restart sssd

}

function linuxHardening(){
    # Remove all unsecure packages
    print"$red\nRemoving all unncessary packages..."
    apt-get --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server $Supressor

    # Update and Upgrade
    print"$red\nUpdating and Upgrade in Progress..."
    apt-get update && apt-get upgrade -y $Supressor

    # Check passwd
    if [$UIDCheck == 'root:x:0:0:root:/root:/bin/bash'] 
    then
        echo "$green You Are Safe!"
    else
        echo "Do This"
    fi

    # Install secure Applications
    apt-get install ufw fail2ban logwatch

    # Configure a firewall
    ufw enable
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh

    # Configure fail2ban
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sed -i 's/destemail = root@localhost/destemail = your@email.com/' /etc/fail2ban/jail.local
    sed -i 's/action = %(action_)s/action = %(action_mw)s/' /etc/fail2ban/jail.local
    service fail2ban restart

    # Configure logwatch
    echo 'detail = Low' >> /etc/logwatch/conf/logwatch.conf

    # Configure SSH
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
    service ssh restart

    # Configure kernel parameters
    echo "kernel.randomize_va_space=1" >> /etc/sysctl.conf
    echo "kernel.exec-shield=1" >> /etc/sysctl.conf
    echo "kernel.core_uses_pid=1" >> /etc/sysctl.conf
    echo "kernel.kptr_restrict=1" >> /etc/sysctl.conf
    echo "kernel.dmesg_restrict=1" >> /etc/sysctl.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    echo "fs.protected_hardlinks = 1" >> /etc/sysctl.conf
    echo "fs.protected_symlinks = 1" >> /etc/sysctl.conf

    # Configure PAM
    sed -i 's/pam_unix.so/pam_unix.so remember=5/' /etc/pam.d/common-password
    sed -i 's/pam_unix.so/pam_unix.so retry=3/' /etc/pam.d/common-auth

    # Configure user account policies
    for user in $(cut -d: -f1 /etc/passwd); do
        # Set minimum password age to 7 days
        chage -m 7 $user
        # Set maximum password age to 90 days
        chage -M 90 $user
        # Set password warning period to 7 days
        chage -W 7 $user
        # Lock user accounts that haven't been used in 90 days
        usermod -L -f 60 $user
    done
}
