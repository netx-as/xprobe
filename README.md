# xProbe

xProbe is a 10Gbe NetFlow exporter based on AF\_XDP backend.

## Installation

AF_XDP required a kernel 4.19+ support. It's mandatory to use ''CONFIG_XDP_SOCKETS=y'' flag when kernel is compiled. How to compile latest vanilla kernel you will see bellow [credits](https://blogs.igalia.com/dpino/2019/01/02/build-a-kernel/): 

```bash
git clone https://github.com/torvalds/linux.git 
cp /boot/config-*-generic ./.config
echo "CONFIG_XDP_SOCKETS=y" >> .config
echo "CONFIG_XDP_SOCKETS_DIAG=y" >> .config (optional for kernel 5.1+, allowed XDP sockets monitoring interface)
sudo make -j4 && sudo make modules_install INSTALL_MOD_STRIP=1
make install
vi /etc/default/grub
add IOMMU PT option: GRUB_CMDLINE_LINUX=... iommu=pt intel_iommu=on
reboot
```



Install [libbpf](https://github.com/libbpf/libbpf) first. How to install you can read [here](https://github.com/libbpf/libbpf/blob/master/README). It's something like this:

```bash
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
mkdir build root
OBJDIR=build DESTDIR=/ make install
```



```bash
make
make run
make clean
```

## Usage

```
  Usage: xProbe [OPTIONS]
  Options:
  -r, --rxdrop		Discard all incoming packets (default)
  -t, --txonly		Only send packets
  -l, --l2fwd		MAC swap L2 forwarding
  -i, --interface=n	Run on interface n
  -q, --queue=n	Use queue n (default 0)
  -p, --poll		Use poll syscall
  -S, --xdp-skb=n	Use XDP skb-mod
  -N, --xdp-native=n	Enfore XDP native mode
  -n, --interval=n	Specify statistics update interval (default 1 sec).
  -z, --zero-copy      Force zero-copy mode.
  -c, --copy           Force copy mode.
```


## Contributing

## License
Ondrej Ploteny, xplote01@stud.fit.vutbr.cz
VUTBR FIT 2019
