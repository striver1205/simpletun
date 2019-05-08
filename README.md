# simpletun
fork simpletun from  Davide

**HOWDO:**

```text
Test Platfrom:
	client/server both with ubuntu18.04
	client, eth0: 192.168.3.100 tunC: 5.5.5.5
	server, eth0: 192.168.3.105 tunS: 5.5.5.1
```

**client:**

```text
Add default route table, not fix original static RIB, here all the packet will 
transfer to simpletun by tunnel interface tunC.

* make sure server's IP pass by real socket interface.
	route add -host 192.168.3.105 dev eth0

* hold up traffic to tunnel interface tunC
	route add -net 0.0.0.0/1   dev tunC 
	route add -net 128.0.0.0/1 dev tunC
```

**server:**

```shell
* Need configure SNAT for server
	iptables -t nat -A POSTROUTING -s 5.5.0.0/16 -j SNAT --to 192.192.168.3.105
```

**check:**

```shell
    ping 5.5.5.1
    ping 5.5.5.5
    ping 8.8.8.8
```


