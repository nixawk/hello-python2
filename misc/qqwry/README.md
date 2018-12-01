
# qqwry

**qqwry.dat** is a binary file which contains ip-related locations information.
This module search it and get location information from it.

## Usage:

**query a single ip**

```
>>> from qqwry import QQwry
>>> qqWry = QQwry('qqwry.dat')
>>> qqWry.ip_location('8.8.8.8')
    ...
```

**query a ip file**

```
>>> from qqwry import QQwry
>>> qqWry = QQwry('qqwry.dat')
>>> for ip in qqWry.ip_file: print(ip_location(ip))
```

Note: pleaes get qqwry ip database from trust sources.


## License

![MIT License](license.txt)
