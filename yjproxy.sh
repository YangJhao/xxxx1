#!/bin/bash
rpm -ivh /root/3proxy-0.9.4-2.el7.x86_64.rpm
sleep 2
mkdir /etc/3proxy
touch /etc/3proxy/passwd
echo 'xjp:CL:zxc@xjp123456' >> /etc/3proxy/passwd
systemctl enable 3proxy
cat /dev/null > /etc/3proxy.cfg
echo 'daemon' >> /etc/3proxy.cfg
echo 'timeouts 1 5 30 60 180 1800 15 60' >> /etc/3proxy.cfg
echo 'nserver 8.8.8.8' >> /etc/3proxy.cfg
echo 'nserver 223.5.5.5' >> /etc/3proxy.cfg
echo 'nscache 65536' >> /etc/3proxy.cfg
echo 'config /etc/3proxy.cfg' >> /etc/3proxy.cfg
echo 'monitor /etc/3proxy.cfg' >> /etc/3proxy.cfg
echo 'monitor /etc/3proxy/passwd' >> /etc/3proxy.cfg
echo 'users $/etc/3proxy/passwd' >> /etc/3proxy.cfg
echo 'log /var/log/3proxy/3proxy.log D' >> /etc/3proxy.cfg
echo 'logformat "L%Y-%m-%d %H:%M:%S.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"' >> /etc/3proxy.cfg
echo 'archiver gz /bin/gzip %F' >> /etc/3proxy.cfg
echo 'rotate 90' >> /etc/3proxy.cfg
echo 'maxconn 100000' >> /etc/3proxy.cfg
echo 'auth strong' >> /etc/3proxy.cfg
echo 'allow *' >> /etc/3proxy.cfg
echo 'proxy -a -p50001' >> /etc/3proxy.cfg
echo 'socks -a -p60001' >> /etc/3proxy.cfg
echo 'flush' >> /etc/3proxy.cfg
sleep 2
reboot
