Minion SSL/TLS Plugin
=====================

This is a plugin for Minion that executes the sslscan tool to find issues with the SSL/TLS connfiguration of a host.

It currently only does the following checks:

* Check if the obsolete SSLv2 protocol is enabled on the server
* Check if the certificate date period is valid

More checks can be written based on the XML output of `sslscan`.

Important Note
--------------

The sslscan tool is compiled against OpenSSL. Some distributions, like Ubuntu, disable SSLv2 in OpenSSL. This is generally a good idea but it also means that sslscan cannot detect SSLv2 anymore.

Therefore the plugin looks for a version of `sslscan` named `minion-sslscan`. This is a build that is statically linked against OpenSSL 1.0.1e with SSLv2 enabled. This is not ideal but a good interim solution.

