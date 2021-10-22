# Zonecheck
Homepage: https://github.com/icann-dns/zonecheck

![GitHub issues](https://img.shields.io/github/issues/icann-dns/zonecheck?style=plastic)
![GitHub contributors](https://img.shields.io/github/contributors/icann-dns/zonecheck)
![GitHub](https://img.shields.io/github/license/icann-dns/zonecheck)
![PyPI](https://img.shields.io/pypi/v/zonecheck)
![PyPI - Downloads](https://img.shields.io/pypi/dm/zonecheck)

Validate DNS zones against DNS master servers and create custom facts.

To be used in tandem with [puppet-dns module](https://github.com/icann-dns/puppet-dns)

## Requirements
- `dnspython`: https://pypi.org/project/dnspython/
- `PyYAML`: https://pypi.org/project/PyYAML/

## Usage
```console
usage: zonecheck [-h] [--serial-lag SERIAL_LAG] [--log LOG] [--puppet-facts]
                 [--puppet-facts-dir PUPPET_FACTS_DIR] [--config CONFIG] [-v]

optional arguments:
  -h, --help            show this help message and exit
  --serial-lag SERIAL_LAG
                        alert if the serial is behind by this value or more
  --log LOG             location of error file
  --puppet-facts
  --puppet-facts-dir PUPPET_FACTS_DIR
  --config CONFIG       comma seperated list of zones
  -v, --verbose
```
