A mirage network performance test script (www.)


Test environment
----------------

Xen server with internet/network connection to download required packages, and for the traffic generator to request IP address from DHCP server.


To use
------

Run the following command on the Xen server:

```
sudo bash mir-perf.sh <library> <version>
```

```library``` is the name of mirage library for the performance test. For the first release, we only support ```mirage-net-xen```. In the above command, ```version``` is the version number (commit hash) of the library on the github. For instance, you can write:

```
sudo bash mir-perf.sh mirage-net-xen b06361d
```

Test configuration
------------------
mirage-net-xen
--------------

 _________                 _________
|         | eth0     tap0 |         |tap1
|traff-gen|----       ----|Unikernel|----
|         |   |       |   |         |   |
-----------   |  if1  |   -----------   | if2
______________|_______|_________________|_____
              ---------                 -
                  ^                     ^
Dom0              |_____________________|
                   bmon Bandwith Monitor
                   

