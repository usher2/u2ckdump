Parse and serve fresh Roscomnadzor dump
=======================================

* Use https://github.com/usher2/vigruzki as dump sources server
* Natural signed Roscomnadzor dumps in the `res` folder for test purpose (git lfs)

IMPORTANT NOTE
--------------

This program is a part of [Usher2](https://usher2.club) ecosystem. The gRPC service will never be published

USE
---

* First the program tries to decompress a dump.zip file if it exists
* Second the program tries to parse a dump.xml file if it exists
* Then the program periodically tries to fetch a dump from a dump sources server

FEATURES
-------

* Native IPv4 string to 32-bit integer implementation
* gRPC service for check IPv4, IPv6, URL, Domain
* Parse subnets to RADIX tree

WARNING
-------

* Stream parsing a `<content>...</content>` object is not a good idea. Because we need some checksum on updates before data applying. So I use `Decode()` method for `<content>...</content>` parsing
* I don't trust to any data. I'm not trying to guess unknown errors. Only known patterns. Roskomnadzor officials are such entertainers

TODO
----

* Native RFC3339 parsing
* ~~Parse subnets to RADIX tree~~
* ~~gRPC service for check IPv4, IPv6, URL, Domain~~
* Stream parsing every `<content>...</content>` object including unchanged is the subject for discussion
* RADIX tree code refactoring

---
[![UNLICENSE](noc.png)](UNLICENSE)
