#!/bin/bash

# https://www.77bx.com/497.html
# by StarYu
# Version: 1.1

check_command() {
    command -v "$1" >/dev/null 2>&1 || { echo >&2 "$1 is required but not installed. Aborting. Install required packages and start again"; exit 1; }
}
check_command wget
check_command gunzip

# info
echo -e "\E[1;31mWarning: This disk will be repartitioned.\E[0m"

# password
get_admin_password() {
    read -sp "Enter RouterOS admin password: " admin_password
    echo
    while [ -z "$admin_password" ]; do
        read -sp "RouterOS Admin password cannot be blank. Please enter again: " admin_password
        echo
    done
}
get_admin_password

# down chr && container
wget -N https://download.mikrotik.com/routeros/7.16.1/chr-7.16.1.img.zip && gunzip -c chr-7.16.1.img.zip > chr.img
wget -N https://download.mikrotik.com/routeros/7.16.1/container-7.16.1.npk

mount -o loop,offset=33571840 chr.img /mnt

INTERFACE=$(ip route | grep default | awk '{print $5}')
ADDRESS=$(ip addr show $INTERFACE | grep global | cut -d' ' -f 6 | head -n 1)
GATEWAY=$(ip route list | grep default | cut -d' ' -f 3)
DISK_DEVICE=$(fdisk -l | grep "^Disk /dev" | grep -v "^Disk /dev/loop" | cut -d' ' -f2 | tr -d ':')

cat > /mnt/rw/autorun.scr <<EOF
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set ssh disabled=yes
/ip service set api disabled=yes
/ip service set api-ssl disabled=yes
/user set admin password=$admin_password
EOF

# rosmode
echo -e -n "\x4d\x32\x01\x00\x00\x29\x0b\x4d\x32\x1c\x00\x00\x01\x0a\x00\x00\x09\x00" > /mnt/rw/rosmode.msg

# packages container
mkdir -p /mnt/var/pdb/container
mv -f container-7.16.1.npk /mnt/var/pdb/container/image

umount /mnt

dd if=chr.img of=$DISK_DEVICE bs=4M oflag=sync

echo "OK, Reboot!"

sleep 1

echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger