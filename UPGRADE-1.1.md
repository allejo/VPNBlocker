# UPGRADE FROM 1.0 to 1.1

Version 1.1 of the plug-in makes use of [version 2 of IPHub](https://headwayapp.co/iphub-changelog/iphub-v2-released-25288). This updated API endpoint is faster, more accurate, and is **not** backwards compatible with version 1 of the API.

If you would like to continue to use version 1 of the IPHub API, continue to use the 1.0.x releases of the plug-in. Keep in mind, version 1 is now deprecated and continued support is no longer guaranteed.

## Configuration File Changes

Version 2 of the IPHub API makes use of actual API keys instead of emails. To get your own API key, see the [IPHub API docs](https://iphub.info/api) and [create an account](https://iphub.info/register). There is a free tier available, which should be more than enough for BZFlag servers.

How are these changes reflected in the configuration file?

- The `API_URL` value has changed to version 2 of the API
- The `API_EMAIL` key has been changed to `API_KEY`

**1.0.x Configuration File**

```ini
# This shouldn't really be changed but can be
API_URL = http://legacy.iphub.info/api.php

# The email address used when making API calls (this is your API key in sorts); change this!
API_EMAIL = email@domain.com
```

**1.1.x Configuration File**

```ini
# This shouldn't really be changed but can be
API_URL = http://v2.api.iphub.info/ip/

# Read up on how to get an API key: https://iphub.info/api
API_KEY = ChangeMe
```
