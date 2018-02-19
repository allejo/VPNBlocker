# VPN Blocker

[![GitHub release](https://img.shields.io/badge/release-v1.1.1-blue.svg)](https://github.com/allejo/VPNBlocker/releases/latest)
![Minimum BZFlag Version](https://img.shields.io/badge/BZFlag-v2.4.12+-blue.svg)

A BZFlag plug-in that will make an API call to a third-party service to check whether or not an IP address is a VPN.

## Requirements

- BZFlag 2.4.12+
- C++11
- json-c
  - libjson0-dev (Debian/Ubuntu)
  - json-c-devel (Fedora Linux)
- [JsonObject](https://github.com/allejo/JsonObject)

## Usage

**Loading the plug-in**

Load the plug-in with a single command line argument, which is the path to the required configuration file.

```
-loadplugin VPNBlocker,/path/to/VPNBlocker.cfg
```

**Configuration File**

The configuration file is required to load the plug-in and have it function properly. [A sample configuration is available as VPNBlocker.cfg](https://github.com/allejo/VPNBlocker/blob/master/VPNBlocker.cfg).

| Config Value | Type | Default | Description |
| ------------ | ---- | ------- | ----------- |
| API_URL | string | N/A<sup>*</sup> | The URL where this plug-in will be checking IPs against. |
| API_KEY | string | N/A | The API key used for making requests to IPHub; see [the IPHub website](https://iphub.info/api) |
| ALLOW_VPN | string | NONE | Which players are allowed to use VPNs. See sample configuration for a more in-depth description and supported values |
| MAX_BZID | int | N/A<sup>*</sup> | If `ALLOW_VPN` is set to VERIFIED, this is the maximum BZID allowed to use VPNs. A player with a newer (higher) BZID will not be allowed to use VPNs to prevent players from registering new accounts just to use VPNs. |

<sup>*</sup> The sample configuration file contains the default and recommended values. Refrain from changing these unless you know what you're doing.

**Custom Slash Commands**

| Command | Permission | Description |
| ------- | ---------- | ----------- |
| `/vpnblocklist` | playerList | Displays a list of IPs that have been blocked as VPNs |

## License

MIT
