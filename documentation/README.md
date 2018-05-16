# Firmware plugin

## ubus
router.system info
juci.system defaultreset
juci.system reboot
juci.sysupgrade start

# Network plugin

## ubus
network.device status
network.interface dump
router.net arp
router.net ipv6_neigh
sfp.ddm get-current
sfp.ddm get-voltage
sfp.ddm get-rx-pwr
sfp.ddm get-tx-pwr
uci commit

## config file
/etc/config/network

# Provisioning plugin

## ubus
router.system fs
router.system info
router.system memory-bank
system board

# Sip plugin

## ubus
asterisk.sip registry_status
uci commit

## config file
/etc/config/voice_client

# Wireless plugin

## ubus
router.wireless status
network.device status
uci commit

## config file
/etc/config/wireless

# Dhcp plugin

## ubus
dhcp "ipv6leases
router.network leases

## config file
/etc/config/dhcp
/etc/config/network
