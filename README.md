# Plugin Name

[![GitHub release](https://img.shields.io/github/release/USERNAME/REPO.svg?maxAge=2592000)](https://github.com/USERNAME/REPO/releases/latest)
![Minimum BZFlag Version](https://img.shields.io/badge/BZFlag-v2.4.0+-blue.svg)
[![License](https://img.shields.io/github/license/USERNAME/REPO.svg)](https://github.com/USERNAME/REPO/blob/master/LICENSE.md)

A brief description about what the plugin does should go here

## Requirements

- List any requirements
- this plug-in will require

## Usage

**Loading the plug-in**

You should specify any command line arguments that are needed or lack thereof

```
-loadplugin pluginName...
```

**Configuration File**

If the plugin requires a custom configuration file, describe it here and all of its special values

**Custom BZDB Variables**

These custom BZDB variables must be used with -setforced, which sets BZDB variable <name> to <value>, even if the variable does not exist. These variables may changed at any time in-game by using the /set command.

```
-setforced <name> <value>
```

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| `_myBZBD` | int | 60 | A description of what this value does |

**Custom Slash Commands**

| Command | Permission | Description |
| ------- | ---------- | ----------- |
| `/command <param>` | vote | A description of what this command does, the required parameters, and permission required |

## License

[LICENSE](https://github.com/USERNAME/REPO/blob/master/LICENSE.md)
