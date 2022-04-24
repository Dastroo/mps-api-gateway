#!/bin/bash
if [ "$(whoami)" != root ]; then
    echo Please run this script as root or using sudo
    exit
fi

service_name="mps-api-gateway.service"
cd build || (echo "build does not exist" && exit)
make uninstall
systemctl disable --now $service_name
rm -rv /etc/systemd/system/$service_name || echo no service to uninstall
systemctl daemon-reload || echo cant reload daemon
