# VPN Blocker

[![GitHub release](https://img.shields.io/github/release/allejo/VPNBlocker.svg)](https://github.com/allejo/VPNBlocker/releases/latest)
![Minimum BZFlag Version](https://img.shields.io/badge/BZFlag-v2.4.12+-blue.svg)
[![License](https://img.shields.io/github/license/allejo/VPNBlocker.svg)](./LICENSE.md)

A BZFlag plug-in that will make an API call to a third-party service to check whether or not an IP address is a VPN.

## Requirements

- BZFlag 2.4.12+
- C++11

## Usage

### Loading the plug-in

Load the plug-in with a single command line argument, which is the path to the required configuration file.

```
-loadplugin VPNBlocker,/path/to/VPNBlocker.config.json
```

### Configuration File

The configuration file is required to load the plug-in and have it function properly. [A sample configuration is available as VPNBlocker.config.json](https://github.com/allejo/VPNBlocker/blob/master/VPNBlocker.config.json).

- `allow_vpn` (string) - Configure which players are allowed to use VPNs
  - `none` - No players, so API calls will be made for each player
  - `verified` - Only authenticated players with accounts older than `max_bzid` will be allowed to use VPNs
- `max_bzid` (int) - When `allow_vpn` is set to `verified`, then only players with a BZID **lower** than this value will be allowed to use a VPN
- `report_url` (string) - A POST request will be sent to this URL with information about IPs that were detected as VPNs 
- `block_list_url` (string) - Currently unimplemented
- `services` (object[]) - An array of API URLs to query on the VPN status of an IP

This plug-in checks for an `ALLOWVPN` permission that supersedes the `allow_vpn` setting, so you can allow admins or specific players use VPNs.

#### Services

This plug-in will occasionally have built-in support for certain services. Multiple services can be configured and they are checked in order, one at a time for each VPN check that is needed. If one service classifies the IP as a VPN, it will cancel the remaining API calls for that IP and move on to checking the next IP.

##### IPHub v2

Create an account on [IPHub](https://iphub.info/) and read up on getting [an API key](https://iphub.info/api) from their documentation. A free account is more than enough for a typical BZFlag server.

To use IPHub as a service in this plugin, here is the structure of the object. Simply use `iphub` for `type` and set your API key for `key`.

```js
{
  "type": "iphub",
  "key": "CHANGE_ME"
}
```

##### Custom Queries

When a service does not have built-in support, you can create your own definitions by simply defining what a GET request will look like. All fields are **required**, even if they're just `{}` for objects, `[]` for arrays, or `""` for strings.

To create your own request, use `custom` for the `type` and define all of the following fields. The special `{ip}` placeholder can be used to define how the player's IP will be sent. This placeholder is available in the following fields:

- `url`
- `query_params`

Here is an example structure to send a GET request to `https://example.com/api.php?ip=127.0.0.1`.

```js
{
  "type": "custom",
  "url": "https://example.com/api.php",
  "query_params": {
    "ip": "{ip}"
  },
  "headers": {
    "X-API-KEY": "CHANGE_ME_MAYBE",
  },
  "response": {
    "report": ["ip"],
    "disallow": {
      "key": "block",
      "value": "1"
    }
  }
}
```

The `response` object defines the logic on *when* to kick a player for VPN usage. 

- The `report` field is a list of `keys` that will be sent to the `report_url` link
- The `disallow` object defines on what key to check and the value that would result in a kick. The `value` definition **must** always be a string; even when the JSON response from the service returns it as a boolean or integer, you will define it as a string in your configuration.

As an example, the following JSON response from `example.com` would result in a kick:

```json
{
  "ip": "127.0.0.1",
  "block": 1
}
```

### Custom Slash Commands

This plug-in implements or overrides the following slash commands.

| Command | Permission | Description |
| ------- | ---------- | ----------- |
| `/reload [vpnblocker]` | setAll | Reload the configuration file this plug-in has loaded |
| `/vpnblocker` | shutdownserver | See the status of the plug-in and see if it's running correctly |
| `/vpnblocklist` | playerList | Displays a list of IPs that have been blocked as VPNs |
| `/vpnunblock` | unban | Remove an IP from the VPN block list loaded in the plug-in's memory |

## License

[MIT](./LICENSE.md)
