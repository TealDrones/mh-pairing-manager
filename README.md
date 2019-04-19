## pairing-manager

Pairing manager listens for pair and connect requests from QGC and responds with configuration and security information needed to establish a secure connection with air vehicle.
Currently supported pairing methods:
- Microhard pairing (QGC sends initial pair request to preconfigured companion computer address and receives response)
- NFC pairing       (QGC receives pair request response as NDEF tag on connect of NFC reader and NFC tag emulator on air vehicle)

Currently supported communication setups:
- Microhard pmDLL modems
- ZeroTier VPN over LTE
- Taisync

Build instructions:
- mkdir build
- cd build
- cmake ..
- make

pairing-manager binary is located in build/src folder.

```
$ pairing-manager -h
pairing-manager [OPTIONS...]

  -n --machine-name       Machine name. Default: BALENA_DEVICE_NAME_AT_INIT or gethostname.
  -m --mavlink-port       MavLink port on which we listen for MAV_CMD_START_RX_PAIR. Default: 14531
  -p --pairing-port       Pairing port on which QGC send pair and connect commands. Default: 29351
  -l --link-type          Link type. MH ... Microhard, ZT ... ZeroTier, TS ... Taisync
  -h --help               Print this message

Microhard specific options:
  -i --ip-prefix          Prefix for Microhard network. Default: 192.168.168
  -a --air-unit-ip        IP of Microhard air unit. Default: 192.168.168.2
  -c --config-password    Configuration password for Microhard Admin user
  -k --pairing-key        Pairing encryption key
  -f --pairing-channel    Pairing channel

ZeroTier specific options:
  -z --zerotier-id        ZeroTier ID

Taisync specific options:
  -e --ethernet-device    Ethernet device to use. Default: eno1
```

Environment variables:
```
PAIRING_MNG_DEVICE_NAME           equivalent to -n
PAIRING_MNG_TYPE                  equivalent to -l
PAIRING_MNG_IP_PREFIX             equivalent to -i
PAIRING_MNG_AIR_UNIT_IP           equivalent to -a
PAIRING_MNG_PAIRING_PORT          equivalent to -p
PAIRING_MNG_CONFIG_PWD            equivalent to -c
PAIRING_MNG_ENCRYPTION_KEY        equivalent to -k
PAIRING_MNG_PAIRING_CHANNEL       equivalent to -f
PAIRING_MNG_ZEROTIER_ID           equivalent to -z
PAIRING_MNG_ETHERNET_DEVICE       equivalent to -e
```

