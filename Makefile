CC = gcc
SOURCE = main.c pkt_proc.c hash.c
TARGET = xProbe
LDFLAGS = -pthread -lbpf -lelf

.PHONY: xdp_sock clean run_help run free

# -L/home/admin/xplote01/libbpf/src/root/usr/lib64/  
#rewrite -I libbpf source directory if needed
xdp_sock:
	$(CC) $(SOURCE) -o $(TARGET)  -I/home/admin/xplote01/libbpf/include/  $(LDFLAGS)

XDPfree:
	ip link set dev tge3 xdp off




clean:
	rm *.o $(TARGET)

run_help:
	./$(TARGET) --help

run:
	taskset -c 1 ./$(TARGET) -i fge11  -N -z
	
