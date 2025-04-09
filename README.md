QuicSand
=========

Description
------------

QuicSand is an automated QUIC protocol performance testing tool that returns benchmark information to help developers know which implementation suits your project the best.

Installation
-------------

For the usage of the tool, there is an implementations folder supposed to add the implementations and build libraries there.

```
git clone https://github.com/TiagoDuarte25/quicsand-app.git
git submodules update --init --recursive
```

Usage
------

1. For containerized application deployment

```
quicsand-cli -c <tests_file> -t <topologies_file>
```

Features
---------

1. Automate client and server metrics collection for every implementation

2. Network Scenario freedom selection

<!-- Contributing
-------------

We welcome contributions from the community to enhance QuicSand's capabilities:

- Fork the repository and make your desired changes.
- Submit a pull request detailing the modifications.
- Engage in code reviews and discussions for collaborative improvement.


License
--------

QuicSand is licensed under the [Insert License Name] license. Refer to the LICENSE file for more details. -->
