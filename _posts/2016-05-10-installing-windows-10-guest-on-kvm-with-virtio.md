---
layout: post
title: Installing Windows 10 guest on KVM with Virtio
---

My Windows 7 virtual machine on KVM became to consume 50GB of disk space on its `C:\Windows`. I finally made my mind up to try Windows 10 as a KVM guest.

### Virtio Driver

Since pure Windows 10 images doesn't shipped with Virtio driver, we should manually provide Virtio drivers during the installation. The Fedora Project provides the driver packages [here](https://fedoraproject.org/wiki/Windows_Virtio_Drivers), so we can just use the iso image.

So far, stable version of driver package doesn't seems to support Windows 10 officially. However I've encountered no problems yet with drivers for Windows 8.1.

### Defining Guest

You can use [virt-install](http://manpages.ubuntu.com/manpages/precise/man1/virt-install.1.html) or start with definition of an existing VM. Here is an example of definition XML I've used:

```xml
<domain type='kvm'>
  <name>VM-NAME</name>
  <memory unit='KiB'>4194304</memory>
  <currentMemory unit='KiB'>4194304</currentMemory>
  <vcpu>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc-i440fx-trusty'>hvm</type>
    <boot dev='hd'/>
    <boot dev='cdrom'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <pae/>
  </features>
  <cpu mode='host-model'/>
  <clock offset='localtime'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>restart</on_crash>
  <devices>
    <emulator>/usr/bin/kvm-spice</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='PATH-TO-DISK-IMAGE'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='PATH-TO-INSTALLATION-IMAGE'/>
      <target dev='hda' bus='ide'/>
      <readonly/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='PATH-TO-VIRTIO-DRIVER-IMAGE'/>
      <target dev='hdb' bus='ide'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <input type='tablet' bus='usb'/>
    <graphics type='vnc' port='5901'/>
    <console type='pty'/>
    <video>
      <model type='vga'/>
    </video>
  </devices>
</domain>
```

- There is an [issue](https://social.technet.microsoft.com/Forums/en-US/695c8997-52cf-4c30-a3f7-f26a40dc703a/failed-install-of-build-10041-in-the-kvm-virtual-machine-system-thread-exception-not-handled?forum=WinPreview2014Setup) about CPU model with Windows 10 as a KVM guest. Just putting `<cpu mode='host-model'/>` resolved the issue on Intel Nehalem.

- Make sure you have two cdrom drives for Windows installation: one for installation image, the other for Virtio driver image.

- Note that default option for disk and network interface is to emulate IDE and Realtek NIC, so you should manually designate to use Virtio. Depending on libvirt version, memballoon with virtio will be automatically added once you define the guest.

- Don't forget the VNC! You'll need it during installation. Also make sure not to expose unsecured VNC port to public internet.

### Installing Windows

Nothing special except you won't see your disk, since the driver is not loaded yet. In disk selection window, load following drivers for Windows 8.1 as needed:

- `NetKVM/` for Virtio Network Interface driver

- `viostor/` for Virtio Blcok Device driver

- `Balloon/` for Virtio Memory Balloon driver

### Done

That's all, congratulations, now you can use Windows VM without Windows 10 upgrade message!
