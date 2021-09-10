P4C ?= $(SDE_INSTALL)/bin/bf-p4c

all: .ndp.ts

.ndp.ts: ndp.p4 common/util.p4 common/headers.p4
ifndef SDE_INSTALL
	$(error SDE_INSTALL is undefined)
endif
	$(P4C) $(OPT) $< --bf-rt-schema ndp.tofino/bfrt.json
	cp -r ndp.tofino $(SDE_INSTALL)/
	@touch $@

package:
	tar -cvf ndp.tar -T package.txt

clean:
	rm -rf .ndp.ts ndp.tar
	rm -rf .dodtest.ts

.PHONY: clean package
