#!/bin/bash

echo "y" | bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh)

sleep 10

default_username="yjh001"
default_password="yjh002"
default_port="45612"

/usr/local/x-ui/x-ui setting -username ${default_username} -password ${default_password}
/usr/local/x-ui/x-ui setting -port ${default_port}

systemctl restart x-ui

echo "x-ui 已经被安装并且配置完成。"