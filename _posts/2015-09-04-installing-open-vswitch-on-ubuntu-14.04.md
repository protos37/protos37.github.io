---
layout: post
title: Installing Open vSwitch on Ubuntu 14.04
---

Open vSwitch is a production quality, multilayer virtual switch licensed under the open source Apache 2.0 license. This guide shows how to install and configure Open vSwitch properly on Ubuntu 14.04.

### Installing Open vSwitch

```sh
sudo apt-get install openvswitch-switch openvswitch-common
```

### Creating virtual bridge

```sh
sudo ovs-vsctl add-br ovsbr0
```
You can consider ovsbr0 as an actual switch. Open vSwitch will switch packets between ports in osvbr0.

### Connecting physical NIC to virtual bridge

Let's say your physical NIC is eth0.

```sh
sudo ovs-vsctl add-port ovsbr0 eth0
```

### Creating virtual port
```sh
sudo ovs-vsctl add-port ovsbr0 ovsbr0p0
sudo ovs-vsctl set interface ovsbr0p0 type=internal
```

You can consider ovsbr0p0 as an actual NIC connected to ovsbr0. You can add more ports same way.

### Configuring network interfaces
Edit `/etc/network/interfaces` like below:

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet manual

auto ovsbr0p0
iface ovsbr0p0 inet dhcp
```

Mind that you should consider ovsbr0p0 as your host's main NIC, not eth0.

And reboot:

```sh
sudo reboot
```

### Done

After booting, nothing should be different from before except name of your main NIC and some Open vSwitch processes. Including ovsbr0p0, ports in ovsbr0 will behave as it's in same subnet with your host's physical NIC.
