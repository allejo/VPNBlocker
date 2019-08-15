# UPGRADE FROM 1.2 to 2.0

Version 1.2 of VPNBlocker is now end-of-life and has been superseded by 2.0. Here's a summary of what version 2.0 of this plug-in entails:

- The configuration file is now a JSON file and is *not* backward-compatible with version 1.2
- The `json-c` dependency has been dropped, no more pesky linking and installing of dependencies
- Custom API endpoints can now be added with ease
- IPHub API v2 is still a first-class citizen

## Compiling

You will likely need to perform an `./autogen.sh` and `./configure` on *nix systems when compiling the new version of the plugin because the `Makefile.am` has changed.

## Upgrading the Configuration File

The configuration file has changed from the old INI format to JSON solely because INI files are not powerful enough to write complex configurations easily.

> Be warned, the old INI files required that its settings and values be in upper case, the JSON format requires that they be in lowercase.

You will **not** be able to copy paste the following snippet into your configuration because it contains comments. The following snippet only has comments for easier explanations and demonstration purposes. Make a copy of the provided JSON configuration file in the repo for your actual version.

```javascript
{
  // The equivalent of the `ALLOW_VPN` setting
  "allow_vpn": "none",

  // The equivalent of the `MAX_BZID` setting
  "max_bzid": 57863,

  // There can now be multiple services configured in this plug-in, one of which
  // is IPHub
  "services": [
    {
      // This special value has been replaced the new for `API_URL` 
      "type": "iphub",

      // This field takes the place of `API_KEY`
      "key": "ChangeMe"
    }
  ],

  // The equivalent of the `VPN_BLOCKLIST_URL` setting. In the INI format, the
  // special value of `0` disabled this functionality. Now, it's an empty string
  "block_list_url": "",

  // The equivalent of the `VPN_REPORT_URL` setting. In the INI format, the
  // special value of `0` disabled this functionality. Now, it's an empty string
  "report_url": ""
}
```
