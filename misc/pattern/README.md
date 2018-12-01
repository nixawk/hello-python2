## Pattern

Metasploit's pattern generator is a great tool, but Ruby's startup time is abysmally slow. 

```
$ python pattern.py
[*] Usage: python pattern.py [option]
    python pattern.py create 5000
    python pattern.py offset 5000 [Ae2A | 41653241]
```

**pattern create**

```
$ python pattern.py create 50
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab
```

**pattern offset**

```
$ python pattern.py offset 50 b1Ab
offset: 34
```

## References

- https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/
- https://www.offensive-security.com/metasploit-unleashed/writing-an-exploit/
- https://github.com/rapid7/metasploit-framework/tree/master/tools/exploit
