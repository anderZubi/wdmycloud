#!/bin/bash

echo Backup your sources.list
cp /etc/apt/sources.list /etc/apt/sources.list.bak

echo Add the sid repo to sources.list
echo deb http://ftp.us.debian.org/debian/ sid main >> /etc/apt/sources.list

echo Update the sid packages list
apt-get update

echo Install Transmission - When asked to continue the installation type Y and hit enter
apt-get install transmission-cli transmission-common transmission-daemon

echo Stop Transmission so you can edit the settings.json file
/etc/init.d/transmission-daemon stop

echo Set Transmission to run as ROOT
sed -i 's/USER=debian-transmission/USER=root /g' /etc/init.d/transmission-daemon

echo Disable the dashboard login
sed -i 's/"rpc-authentication-required": true,/"rpc-authentication-required": false,/g' /etc/transmission-daemon/settings.json

echo Disable the RPC whitelist so you can access the Transmission GUI
sed -i 's/"rpc-whitelist-enabled": true,/"rpc-whitelist-enabled": false,/g' /etc/transmission-daemon/settings.json

echo Move back your original sources.list
mv -f /etc/apt/sources.list.bak /etc/apt/sources.list
 
# OPTIONAL but recommended for those wishing to have access to the actual .torrent files easily from the DataVolume
 
echo Create a folder called torrents in your Public folder

rmdir /var/lib/transmission-daemon/info/torrents
ln -s /DataVolume/shares/Public/torrents /var/lib/transmission-daemon/info/torrents

########

echo Then to start Transmission again
/etc/init.d/transmission-daemon start

echo Transmission is installed and running

echo For login to the Transmission GUI use
echo your mycloud ip or network name:9091
 
echo Click the wrench icon on the bottom left to set location for downloads
echo In the Download To box enter /DataVolume/shares/Public/Transmission or any share on your MyCloud