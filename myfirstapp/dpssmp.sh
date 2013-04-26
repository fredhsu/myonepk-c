IP=`ifconfig wlan0 | grep 'inet addr' | cut -d: -f2| awk '{ print $1 }'`
sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$IP/ /opt/cisco/onep/c64/sdk-c64-0.7.0.503g/c/bin/dpss.conf > /opt/cisco/onep/c64/sdk-c64-0.7.0.503g/c/bin/dpss.conf

echo "be sure to change dpss.conf for local ip address $IP"
sudo LD_LIBRARY_PATH=/opt/cisco/onep/c64/sdk-c64-0.7.0.503g/c/lib/ /opt/cisco/onep/c64/sdk-c64-0.7.0.503g/c/bin/dpss_mp_64-0.7.0.503
