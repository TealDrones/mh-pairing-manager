## pairing-manager

Pairing manager listens for pair and connect requests from QGC and responds with configuration and security information needed to establish a secure connection with air vehicle.
Currently supported pairing methods:
- Microhard pairing (QGC sends initial pair request to preconfigured companion computer address and receives response)
- NFC pairing       (QGC receives pair request response as NDEF tag on connect of NFC reader and NFC tag emulator on air vehicle)

Currently supported communication setups:
- Microhard pmDLL modems
- ZeroTier VPN over LTE
- Taisync

Library Dependencies for Ubuntu 18.04:
- sudo apt install -y ragel libssl-dev libudev-dev libboost-all-dev

Build instructions:
- git submodule update --init --recursive
- mkdir build
- cd build
- cmake ..
- make

pairing-manager binary is located in build/src folder.

```
$ pairing-manager -h
pairing-manager [OPTIONS...]

  -n --machine-name       Machine name. Default: BALENA_DEVICE_NAME_AT_INIT or gethostname.
  -d --persistent-folder  Folder in which pairing information is permanently stored. Default: /data
  -m --mavlink-port       MavLink port on which we listen for MAV_CMD_START_RX_PAIR. Default: 14531
  -p --pairing-port       Pairing port on which QGC send pair and connect commands. Default: 29351
  -l --link-type          Link type. MH ... Microhard, ZT ... ZeroTier, TS ... Taisync
  -k --pairing-key        Pairing encryption key
  -h --help               Print this message

Microhard specific options:
  -i --ip-prefix          Prefix for Microhard network. Default: 192.168.168
  -a --air-unit-ip        IP of Microhard air unit. Default: 192.168.168.2
  -c --config-password    Configuration password for Microhard Admin user
  -s --pairing-net-id     Microhard pairing network id. Default: MH
  -f --pairing-channel    Pairing channel

ZeroTier specific options:
  -z --zerotier-id        ZeroTier ID

Taisync specific options:
  -e --ethernet-device    Ethernet device to use. Default: eno1
```

Environment variables:
```
PAIRING_MNG_DEVICE_NAME           equivalent to -n
PAIRING_MNG_PERSISTENT_FOLDER     equivalent to -d
PAIRING_MNG_TYPE                  equivalent to -l
PAIRING_MNG_IP_PREFIX             equivalent to -i
PAIRING_MNG_AIR_UNIT_IP           equivalent to -a
PAIRING_MNG_PAIRING_PORT          equivalent to -p
PAIRING_MNG_CONFIG_PWD            equivalent to -c
PAIRING_MNG_ENCRYPTION_KEY        equivalent to -k
PAIRING_MNG_PAIRING_NETWORK_ID    equivalent to -s
PAIRING_MNG_PAIRING_CHANNEL       equivalent to -f
PAIRING_MNG_ZEROTIER_ID           equivalent to -z
PAIRING_MNG_ETHERNET_DEVICE       equivalent to -e
```

