Parse and serve fresh Roscomnadzor dump
=======================================

* Use https://github.com/usher-2/vigruzki as dump sources server
* Natural signed Roscomnadzor dumps in the `res` folder for test purpose (git lfs)

IMPORTANT NOTE
--------------

This program is a part of [https://usher2.club](Usher2) ecosystem. The gRPC service will never be published

USE
---

* First the program try to unzip dump.zip if exists
* Second the program try to parse dump.xml if exists
* Than the program try to fetch and parse dump from dump sources server periodically

FUTURES
-------

* Native IPv4 string to 32-bit integer implementation

WARNING
-------

* Stream parsing a `<content>...</content>` object is not a good idea. Because we need some checksum on updates before data applying. So I use `Decode()` method for `<content>...</content>` parsing
* I don't trust to any data. I'm not trying to guess unknown errors. Only known patterns. Roskomnadzor officials are such entertainers

TODO
----

* Native RFC3339 parsing
* Parse subnet to RADIX tree
* gRPC service for check IPv4, IPv6, URL, Domain
* Stream parsing every `<content>...</content>` object including unchanged is the subject for discussion

---
[![UNLICENSE](noc.png)](UNLICENSE)
