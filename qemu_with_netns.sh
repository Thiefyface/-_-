
ip netns add qemu
ip link add qemu-h type veth peer name qemu-g

ip link set qemu-g netns qemu
ip netns exec qemu ip link add br0 type bridge
ip netns exec qemu ip link set dev lo up
ip netns exec qemu ip tuntap add tap0 mode tap
ip netns exec qemu echo 1 > /proc/sys/net/ipv4/ip_forward

ip netns exec qemu brctl addif br0 qemu-g
ip netns exec qemu brctl addif br0 tap0
ip netns exec qemu ip link set dev br0 up

ip netns exec qemu ip addr add 172.16.10.1/24 dev qemu-g
#ip netns exec qemu ip addr add 172.10.2.1/24 dev tap0  # can I do this from outside vm?
ip netns exec qemu ip link set dev tap0 up
ip netns exec qemu ip route add 172.16.20.0/24 dev br0 
ip netns exec qemu ip route add 192.168.1.0/24 dev br0
ip netns exec qemu echo 1 > /proc/sys/net/ipv4/ip_forward

ip addr add 172.16.20.1/24 dev qemu-h 
ip link set dev qemu-h up
ip netns exec qemu ip link set dev qemu-g up 
ip netns exec qemu ip route add 172.16.20.0/24 dev br0
ip route add 172.16.10.0/24 dev qemu-h 
ip route add 192.168.1.0/24 dev qemu-h via 172.16.10.1


echo -e "[^_^] Networking setup, please remember to \n \`ip route add 172.16.10.0/24 dev br-lan\` \n \`ip route add 172.16.20.0/24 dev br-lan via 172.16.10.1\` "
echo "[you:172.16.20.1]----[veth[qemu netns]veth:172.16.10.1]-----[br0]----|[qemu instance:192.168.1.1]"
sleep 2

ip netns exec qemu qemu-system-arm -M virt-2.9 \
 -kernel zImage \
 -no-reboot -nographic \
 -drive file=new_rootfs.ext4,if=virtio,format=raw\
 -append "root=/dev/vda" \
 -netdev tap,ifname=tap0,script=no,downscript=no,id=my_net_id \
 -device driver=virtio-net,netdev=my_net_id

ip netns exec qemu ip link del tap0 
ip netns exec qemu ip link del qemu-g 
ip netns exec qemu ip link del br0
ip netns del qemu






