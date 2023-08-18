# iOS Restriction Passcode Brute Force ![Version](https://img.shields.io/badge/Version-3.0.0-blue.svg?style=flat-square)

[![Python](https://img.shields.io/badge/Python-2.7%20&%203.6-orange.svg?style=flat-square)](https://www.python.org/downloads/release/python-2714/) ![OS](https://img.shields.io/badge/Works%20On-Linux%20|%20macOS%20|%20Windows%20-green.svg?style=flat-square) ![iOS](https://img.shields.io/badge/Tested%20On%20iOS-9.3.5%20|%2010.0.1%20|%2011.2.1-green.svg?style=flat-square) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![Code Climate](https://img.shields.io/codeclimate/maintainability/thehappydinoa/iOSRestrictionBruteForce.svg?style=flat-square)](https://codeclimate.com/github/thehappydinoa/iOSRestrictionBruteForce)

## Overview

This version of the application is written in Python, which is used to crack the restriction passcode of an iPhone/iPad takes advantage of a flaw in unencrypted backups allowing the hash and salt to be discovered.

![Restriction Passcode](docs/ios-restrictions.jpeg)

## DEPENDENCIES

This has been tested with [Python 2.7](https://www.python.org/downloads/release/python-271/) and [Python 3.7](https://www.python.org/downloads/release/python-365/)

Requires [requests][def] Install with `pip install requests`

## Usage

```usage
usage: ioscrack.py [-h] [-c] [--mojave] [-b folder]

a script to crack the restriction passcode of an iDevice

optional arguments:
-h, --help            show this help message and exit
-c, --cli             prompts user for input
-m, --mojave              helps user run script on macOS mojave
-b folder, --backup folder
                    where backups are located
```

## How to Use

1. Clone repository

   ```bash
   git clone https://github.com/thehappydinoa/iOSRestrictionBruteForce && cd iOSRestrictionBruteForce
   ```

2. Make sure to use [iTunes](https://www.apple.com/itunes/download/) or [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) to backup the iOS device to computer

3. Run `ioscrack.py`

   ```bash
   python ioscrack.py
   ```

![GIF](docs/ioscrack.gif)

## How It Works

Done by cracking the [pbkdf2](http://www.ietf.org/rfc/rfc2898.txt) hash with my lambda function using Passlib

1. Tries the [top 20 four-digit](http://www.datagenetics.com/blog/september32012/index.html) pins

2. Tries birthdays between 1000-(50 years into the future)

3. Brute force pins from 1 to 9999

4. Adds successful pins to local database

## How to Protect Against

1. Encrypt backups

2. Backup only on trusted computers

## Notes

You may have trouble accessing `~/Library/Application\ Support/MobileSync/Backup/` on macOS Mojave and higher as SIP (System Integrity Protection) prevents programmatic access to that folder. The way around this is to copy the folder `Backup` from the above path to the `iOSRestrictionBruteForce` folder then run `python ioscrack.py -b Backup`. Or run `python ioscrack.py --mojave`

## Contributing

Best ways to contribute

- Star it on GitHub - if you use it and like it please at least star it :)
- [Promote](#promotion)
- Open [issues](https://github.com/thehappydinoa/iOSRestrictionBruteForce/issues)
- Submit fixes and/or improvements with [Pull Requests](http://makeapullrequest.com)
- Add to the [wiki](https://github.com/thehappydinoa/iOSRestrictionBruteForce/wiki)

## Promotion

Like the project? Please support to ensure continued development going forward:

- Star this repo on [GitHub](action:files#disambiguate)
- Follow me

  - [Twitter](https://twitter.com/thehappydinoa)
  - [GitHub](https://github.com/thehappydinoa)

## Acknowledgments

- [yuejd](https://github.com/yuejd)

## LICENSE

[MIT License](LICENSE)


[def]: http://docs.python-requests.org/en/master/