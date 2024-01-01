<p align="center">
   <img width="300" height="auto" src="https://i.imgur.com/sD8cjJc.png">
 </p>

# Infrared - a Minecraft Proxy

fork of [haveachin/infrared](https://github.com/haveachin/infrared)

## TODO
- Make encryption check use 1.19 signatures

## Added/changed Features

- Default configurable placeholder for invalid domain and kick message
- Antibot based on ip lookups, encryption checks, authentication checks, protocol checks and username lookups
- Caching in redis server (can be used for multiple instances)
- Added handshakes and blocked connections(multiple types) to prometheus exporter
- Allow multiple domains in 1 configfile
- Global .yml config
- Removed docker and callback features
- Status packet caching
- Bandwith usage tracking for proxy configs through prometheus
- Use redis to get proxy configs ([lhridder/infrapi](https://github.com/lhridder/infrapi))
- Live upgrades using [tableflip](https://github.com/cloudflare/tableflip)
- Dual stack (both IPv4 and IPv6 are supported)

## Command-Line Flags

`-config-path` specifies the path to all your server configs [default: `"./configs/"`]

### Example Usage

`./infrared -config-path="."`

## Global config.yml
### Example/Default
```yaml
debug: false
receiveProxyProtocol: false
useRedisConfigs: false
underAttack: false
connectionThreshold: 50
trackBandwidth: false
prometheus:
  enabled: false
  bind: :9070
api:
  enabled: false
  bind: :5000
mojangAPIenabled: false
geoip:
  enabled: false
  databaseFile:
  enableIprisk: false
redis:
  host: localhost
  pass:
  db: 0
configredis:
  host: localhost
  pass:
  db: 0
rejoinMessage: Please rejoin to verify your connection.
blockedMessage: Your ip is blocked for suspicious activity.
genericJoinResponse: There is no proxy associated with this domain. Please check your configuration.
genericping:
  version: infrared
  description: There is no proxy associated with this domain. Please check your configuration.
  iconPath: 
tableflip:
  enabled: false
  pidfile: infrared.pid
```
Values can be left out if they don't deviate from the default, an empty config.yml is still required for startup.
### Fields
- `receiveProxyProtocol` whether to allow for inbound proxyProtocol connections.
- prometheus:
  - `enabled` whether to enable to builtin prometheus exporter or not.
  - `bind` on what port/address to have the prometheus exporter listen on.
  - `bind2` what secondary port should be used when using tableflip.
- api:
  - `nabled` if the json http api should be enabled.
  - `bind` on what port/address to have the api listen on.
- genericping:
  - `version` what version should be sent with for an unknown domain status request.
  - `description` what description should be sent with for an unknown domain status request.
  - `iconPath` what icon should be sent with for an unknown domain status request.
- `genericJoinResponse` what text response should be sent for an unknown domain join request.
- geoip:
  - `enabled` if geoip lookups should be enabled.
  - `databaseFile` where the .mmdb file is located for geoip lookups.
  - `enableIprisk` whether or not ip lookups should be done through iprisk.info.
- `mojangAPIenabled` whether to enable mojang API username checks (only works if geoip is enabled).
- redis:
  - `host` what redis server to connect to when caching geoip and username lookups.
  - `DB` what redis db should be used on the redis server.
  - `pass` what password should be used when logging into the redis server.
- configredis:
  - `host` what redis server to connect to when fetching and watching configs.
  - `DB` what redis db should be used on the redis server.
  - `pass` what password should be used when logging into the redis server.
- tableflip:
  - `enabled` whether or not tableflip should be used.
  - `pidfile` where the PID file used for tableflip is located.
- `rejoinMessage` what text response should be sent when a player needs to rejoin to verify they're not a bot.
- `blockedMessage` what text response should be sent when an ip address gets blocked.
- `underAttack` if the instance should permanently be in attack mode.
- `debug` if debug logs should be enabled.
- `connectionTreshold` at what amount of packets per second the underAttack mode should trigger.
- `trackBandwith` whether or not bandwith usage should be tracked in prometheus (requires prometheusEnabled).
- `useRedisConfigs` whether or not to get the proxy configs from redis (this will disable the builtin api).

## Proxy Config

| Field Name        | Type      | Required | Default                                        | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|-------------------|-----------|----------|------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| domainNames       | String[]  | true     | localhost                                      | Should be [fully qualified domain name](https://en.wikipedia.org/wiki/Domain_name). <br>Note: Every string is accepted. So `localhost` is also valid.                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| listenTo          | String    | true     | :25565                                         | The address (usually just the port; so short term `:port`) that the proxy should listen to for incoming connections.<br>Accepts basically every address format you throw at it. Valid examples: `:25565`, `localhost:25565`, `0.0.0.0:25565`, `127.0.0.1:25565`, `example.de:25565`                                                                                                                                                                                                                                                                                                        |
| proxyTo           | String    | true     |                                                | The address that the proxy should send incoming connections to. Accepts Same formats as the `listenTo` field.                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| proxyBind         | String    | false    |                                                | The local IP that is being used to dail to the server on `proxyTo`. (Same as Nginx `proxy-bind`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| disconnectMessage | String    | false    | Sorry {{username}}, but the server is offline. | The message a client sees when he gets disconnected from Infrared due to the server on `proxyTo` won't respond. Currently available placeholders:<br>- `username` the username of player that tries to connect<br>- `now` the current server time<br>- `remoteAddress` the address of the client that tries to connect<br>- `localAddress` the local address of the server<br>- `domain` the domain of the proxy (same as `domainName`)<br>- `proxyTo` the address that the proxy proxies to (same as `proxyTo`)<br>- `listenTo` the address that Infrared listens on (same as `listenTo`) |
| timeout           | Integer   | true     | 1000                                           | The time in milliseconds for the proxy to wait for a ping response before the host (the address you proxyTo) will be declared as offline. This "online check" will be resend for every new connection.                                                                                                                                                                                                                                                                                                                                                                                     |
| proxyProtocol     | Boolean   | false    | false                                          | If Infrared should use HAProxy's Proxy Protocol for IP **forwarding**.<br>Warning: You should only ever set this to true if you now that the server you `proxyTo` is compatible.                                                                                                                                                                                                                                                                                                                                                                                                           |
| realIp            | Boolean   | false    | false                                          | If Infrared should use TCPShield/RealIP Protocol for IP **forwarding**.<br>Warning: You should only ever set this to true if you now that the server you `proxyTo` is compatible.                                                                                                                                                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                      |
| onlineStatus      | Object    | false    |                                                | This is the response that Infrared will give when a client asks for the server status and the server is online.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| offlineStatus     | Object    | false    | See [Response Status](#response-status)        | This is the response that Infrared will give when a client asks for the server status and the server is offline.                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

### Response Status

| Field Name     | Type    | Required | Default         | Description                                                                                                                                          |
|----------------|---------|----------|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| versionName    | String  | false    | Infrared 1.18   | The version name of the Minecraft Server.                                                                                                            |
| protocolNumber | Integer | true     | 757             | The protocol version number.                                                                                                                         |
| maxPlayers     | Integer | false    | 20              | The maximum number of players that can join the server.<br>Note: Infrared will not limit more players from joining. This number is just for display. |
| playersOnline  | Integer | false    | 0               | The number of online players.<br>Note: Infrared will not that this number is also just for display.                                                  |
| playerSamples  | Array   | false    |                 | An array of player samples. See [Player Sample](#Player Sample).                                                                                     |
| iconPath       | String  | false    |                 | The path to the server icon.                                                                                                                         |
| motd           | String  | false    |                 | The motto of the day, short MOTD.                                                                                                                    |

### Examples

#### Minimal Config

<details>
<summary>min.example.com</summary>

```json
{
  "domainNames": ["mc.example.com", "example.com"],
  "proxyTo": ":8080"
}
```

</details>

#### Full Config

<details>
<summary>full.example.com</summary>

```json
{
  "domainNames": ["mc.example.com", "example.com"],
  "listenTo": ":25565",
  "proxyTo": ":8080",
  "proxyBind": "0.0.0.0",
  "proxyProtocol": false,
  "realIp": false,
  "timeout": 1000,
  "disconnectMessage": "Username: {{username}}\nNow: {{now}}\nRemoteAddress: {{remoteAddress}}\nLocalAddress: {{localAddress}}\nDomain: {{domain}}\nProxyTo: {{proxyTo}}\nListenTo: {{listenTo}}",
  "onlineStatus": {
    "versionName": "1.18",
    "protocolNumber": 757,
    "maxPlayers": 20,
    "playersOnline": 2,
    "playerSamples": [
      {
        "name": "Steve",
        "uuid": "8667ba71-b85a-4004-af54-457a9734eed7"
      },
      {
        "name": "Alex",
        "uuid": "ec561538-f3fd-461d-aff5-086b22154bce"
      }
    ],
    "motd": "Join us!"
  },
  "offlineStatus": {
    "versionName": "1.18",
    "protocolNumber": 757,
    "maxPlayers": 20,
    "playersOnline": 0,
    "motd": "Server is currently offline"
  }
}
```

</details>

## Prometheus exporter
The built-in prometheus exporter can be used to view metrics about infrareds operation.
This can be used through `"prometheusEnabled": true` and `"prometheusBind": ":9070"` in `config.yml`
It is recommended to firewall the prometheus exporter with an application like *ufw* or *iptables* to make it only accessible by your own Prometheus instance.
### Prometheus configuration:
Example prometheus.yml configuration:
```yaml
scrape_configs:
  - job_name: infrared
    static_configs:
    - targets: ['infrared-exporter-hostname:port']
```

### Metrics:
* infrared_connected: show the amount of connected players per instance and proxy:
  * **Example response:** `infrared_connected{host="proxy.example.com",instance="vps1.example.com:9070",job="infrared"} 10`
  * **host:** listenTo domain as specified in the infrared configuration.
  * **instance:** what infrared instance the amount of players are connected to.
  * **job:** what job was specified in the prometheus configuration.
* infrared_handshakes: counter of the number of handshake packets received per instance, type and target:
  * **Example response:** `infrared_handshakes{instance="vps1.example.com:9070",type="status",host="proxy.example.com",country="DE"} 5`
  * **instance:** what infrared instance handshakes were received on.
  * **type:** the type of handshake received; "status", "login", "cancelled_host", "cancelled_encryption", "cancelled_name", "cancelled", "cancelled_authentication" and "cancelled_invalid".
  * **country:** country where the player ip is from.
  * **host:** the target host specified by the "Server Address" field in the handshake packet. [[1]](https://wiki.vg/Protocol#Handshaking)

## Mitigation
### GeoIP
Infrared uses maxminds mmdb format for looking up the countries ips originate from.\
The required GeoLite2-Country.mmdb/GeoLite2-City.mmdb can be downloaded from [maxmind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) for free by making an account.

### Configuration
The following configuration settings are recommended for optimal mitigation, keep in mind this requieres a local/online redis server for caching.
```yaml
debug: false
mojangAPIenabled: true
geoip:
  enabled: true
  databaseFile: GeoLite2-Country.mmdb
redis:
  host: localhost
  pass:
  db: 0
```

### System
* Linux kernel >=5.8 (Debian >=11 or Ubuntu >=22.04)
* Increasing `net.core.somaxconn` in sysctl to for example 50000 (default is 4096). Can be done with `sysctl net.core.somaxconn=50000`.
* Increasing the `ulimit` to for example 500000 (default is 1024). Can be done with `ulimit -n 500000` when running in a terminal or `LimitNOFILE=500000` in a systemd service file.

## Tableflip
[Tableflip](https://github.com/cloudflare/tableflip) allows for the golang application to be upgraded live by swapping the binary and creating a new process without killing off existing connections.\
#### Systemd
To use this feature running infrared under systemd is required, here an example of how the .service file should look:
Upgrades can then be triggered with `systemctl reload infrared`.
```text
[Unit]
Description=Infrared
After=network-online.target

[Service]
User=root
Group=root
WorkingDirectory=/srv/infrared
ExecStart=/srv/infrared/infrared
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/srv/infrared/infrared.pid
LimitNOFILE=500000
LimitNPROC=500000

[Install]
WantedBy=multi-user.target
```
#### Configuration
```yaml
tableflip:
  enabled: true
  pidfile: infrared.pid
```

## API
### Route examples
GET `/proxies` will return
```json
[
"config",
"config2"
]
```

GET `/proxies/{name}` will return
```json
{
"domainNames": ["play.example.org"],
"proxyTo": "backend.example.org:25566"
}
```

POST `/proxies/{name}` with body
```json
{
"domainNames": ["play.example.org"],
"proxyTo": "backend.example.org:25566"
}
```
will return
```json
{"success": true, "message": "the proxy has been succesfully added"}
```

DELETE `/proxies/{name}` will return 200(OK)

GET `/` will return 200(OK)

## Used sources
- [Minecraft protocol documentation](https://wiki.vg/Protocol)
- [Minecraft protocol implementation in golang 1](https://github.com/specspace/plasma)
- [Minecraft protocol implementation in golang 2](https://github.com/Tnze/go-mc)
- [Mojang api implementation in golang](https://github.com/Lukaesebrot/mojango)
- [Redis library for golang](https://github.com/go-redis/redis/v8)
- [MMDB geoip library for golang](https://github.com/oschwald/geoip2-golang)
- [Govalidator](https://github.com/asaskevich/govalidator)
- [Mux router](https://github.com/gorilla/mux)
- [Tableflip](https://github.com/cloudflare/tableflip)
