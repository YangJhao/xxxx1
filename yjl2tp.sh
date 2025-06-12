#!/bin/bash
yum install -y epel-release
sleep 2
yum install -y xl2tpd libreswan  net-tools
sleep 2
#配置L2tp文件 
cat /dev/null > /etc/xl2tpd/xl2tpd.conf
echo '[global]' >> /etc/xl2tpd/xl2tpd.conf
echo 'ipsec saref = yes' >> /etc/xl2tpd/xl2tpd.conf
echo 'listen-addr = 0.0.0.0' >> /etc/xl2tpd/xl2tpd.conf
echo 'auth file = /etc/ppp/chap-secrets' >> /etc/xl2tpd/xl2tpd.conf
echo 'port = 1701' >> /etc/xl2tpd/xl2tpd.conf
echo '[lns default]' >> /etc/xl2tpd/xl2tpd.conf
echo 'ip range = 10.254.254.1-10.254.254.100' >> /etc/xl2tpd/xl2tpd.conf
echo 'local ip = 10.0.0.254' >> /etc/xl2tpd/xl2tpd.conf
echo 'refuse chap = yes' >> /etc/xl2tpd/xl2tpd.conf
echo 'refuse pap = yes' >> /etc/xl2tpd/xl2tpd.conf
echo 'require authentication = yes' >> /etc/xl2tpd/xl2tpd.conf
echo 'name = l2tpd' >> /etc/xl2tpd/xl2tpd.conf
echo 'ppp debug = yes' >> /etc/xl2tpd/xl2tpd.conf
echo 'pppoptfile = /etc/ppp/options.xl2tpd' >> /etc/xl2tpd/xl2tpd.conf
echo 'length bit = yes' >> /etc/xl2tpd/xl2tpd.conf
sleep 2
#ppp配置文件
cat /dev/null > /etc/ppp/options.xl2tpd
echo 'ipcp-accept-local' >> /etc/ppp/options.xl2tpd
echo 'ipcp-accept-remote' >> /etc/ppp/options.xl2tpd
echo 'require-mschap-v2' >> /etc/ppp/options.xl2tpd
echo 'ms-dns 8.8.8.8' >> /etc/ppp/options.xl2tpd
echo 'ms-dns 223.5.5.5' >> /etc/ppp/options.xl2tpd
echo 'asyncmap 0' >> /etc/ppp/options.xl2tpd
echo 'auth' >> /etc/ppp/options.xl2tpd
echo 'crtscts' >> /etc/ppp/options.xl2tpd
echo 'lock' >> /etc/ppp/options.xl2tpd
echo 'hide-password' >> /etc/ppp/options.xl2tpd
echo 'modem' >> /etc/ppp/options.xl2tpd
echo 'debug' >> /etc/ppp/options.xl2tpd
echo 'name l2tpd' >> /etc/ppp/options.xl2tpd
echo 'proxyarp' >> /etc/ppp/options.xl2tpd
echo 'lcp-echo-interval 30' >> /etc/ppp/options.xl2tpd
echo 'lcp-echo-failure 4' >> /etc/ppp/options.xl2tpd
echo 'mtu 1450' >> /etc/ppp/options.xl2tpd
echo 'noccp' >> /etc/ppp/options.xl2tpd
echo 'connect-delay 5000' >> /etc/ppp/options.xl2tpd
sleep 2
#配置账号密码  (账号3  服务类型全支持* 密码3 指定IP *随机）

echo '3 * 3 *' >> /etc/ppp/chap-secrets
sleep 2
#初始化并重启防火墙：
systemctl restart firewalld
firewall-cmd --reload
firewall-cmd --zone=public --add-port=1723/tcp --permanent
firewall-cmd --zone=public --add-port=1701/udp --permanent
firewall-cmd --permanent --add-service=gre
firewall-cmd --permanent --add-service=ipsec
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload
firewall-cmd --list-all --zone=public 
#设置开机启动
systemctl enable firewalld
systemctl enable xl2tpd
sleep 2
#重启生效
reboot
