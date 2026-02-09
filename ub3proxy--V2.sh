#!/bin/bash
cd /opt
wget https://github.com/z3APA3A/3proxy/releases/download/0.9.4/3proxy-0.9.4.x86_64.deb
sudo dpkg -i 3proxy-0.9.4.x86_64.deb
sleep 2
echo 'user1:CL:23333' >> /etc/3proxy/passwd
cat /dev/null > /etc/3proxy/3proxy.cfg
echo 'daemon' >> /etc/3proxy/3proxy.cfg
echo 'timeouts 1 5 30 60 180 1800 15 60' >> /etc/3proxy/3proxy.cfg
echo 'nserver 8.8.8.8' >> /etc/3proxy/3proxy.cfg
echo 'nserver 223.5.5.5' >> /etc/3proxy/3proxy.cfg
echo 'nscache 65536' >> /etc/3proxy/3proxy.cfg
echo 'config /etc/3proxy.cfg' >> /etc/3proxy/3proxy.cfg
echo 'monitor /etc/3proxy.cfg' >> /etc/3proxy/3proxy.cfg
echo 'monitor /etc/3proxy/passwd' >> /etc/3proxy/3proxy.cfg
echo 'users $/etc/3proxy/passwd' >> /etc/3proxy/3proxy.cfg
echo 'log /var/log/3proxy/3proxy.log D' >> /etc/3proxy/3proxy.cfg
echo 'logformat "L%Y-%m-%d %H:%M:%S.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"' >> /etc/3proxy/3proxy.cfg
echo 'archiver gz /bin/gzip %F' >> /etc/3proxy/3proxy.cfg
echo 'rotate 90' >> /etc/3proxy/3proxy.cfg
echo 'auth strong' >> /etc/3proxy/3proxy.cfg
echo 'allow *' >> /etc/3proxy/3proxy.cfg
echo 'proxy -a -p50001' >> /etc/3proxy/3proxy.cfg
echo 'socks -a -p60001' >> /etc/3proxy/3proxy.cfg
echo 'flush' >> /etc/3proxy/3proxy.cfg
sleep 2
#防火墙
#sudo ufw allow 50001/tcp
#sudo ufw allow 60001/tcp
#sudo ufw allow 10001:65000/udp
#sudo systemctl disable ufw
#sleep 1
#修改系统 ulimit 设置
ulimit -n 200000
echo '* soft nofile 200000' >> /etc/security/limits.conf
echo '* hard nofile 200000' >> /etc/security/limits.conf

sudo systemctl restart 3proxy





