BMV2_CPU_PORT=255

BMV2_OPTIONS=-DTARGET_BMV2 -DCPU_PORT=$(BMV2_CPU_PORT)

all: bmv2-int

bmv2-int:
	p4c -v -x p4-16 -b bmv2-v1model \
	$(BMV2_OPTIONS) -o p4c-out/bmv2 \
	--p4runtime-file p4c-out/bmv2/switch.p4info \
	--p4runtime-format text switch.p4
	mv p4c-out/bmv2/switch.p4rt p4c-out/bmv2/switch.p4info
	rm -f p4c-out/bmv2/switch.p4i

clean:
	rm -rf p4c-out/*
