# Netgear-SwitchAdmin
Python script to toggle ports on GS105E and GS108E switches


This is my first try on adapting a python script. The original script was created by Corey Anderson [netgear_admin](https://github.com/ElectricLab/netgear_admin) but did not work correctly on my GS105E and GS108E switches.

I've adapted the script so it would identyfy the switch and change some requests.
This script can be used in Home Assistant to remotely toggle network switch-ports on and off.

python netgear_admin.py -a switch_ipaddress -passwd password -p portnumber -s port_status

If -s is set to status, the port status is returned
If -s is set to on, the port is switched on
If -s is set to something else, the port is switched off

