# UPGRADE FROM 1.1 to 1.2

Version 1.2 of the plug-in makes use of `libjson-c-dev` instead of the, deprecated, `libjson0-dev` package on Debian based systems.

What does this mean technically speaking?

It means that in this code, we need to have link the library with `-ljson-c` in the the Makefile and in should be `#include <json-c/json.h>` in the C++ files.

## How to Upgrade

Pull the latest `release` branch and run `autogen.sh`, `configure` and `make` to clear out any references to the old link. If it compiles after you do this, you're all set!

Otherwise, you may need to install `libjson-c-dev`, which is available on Debian 8+ and Ubuntu 14.04+.

```
apt-get install libjson-c-dev
```

That's it!
