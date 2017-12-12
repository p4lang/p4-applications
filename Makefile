
CHARTER=charter

all: ${CHARTER}.pdf

${CHARTER}.pdf: ${CHARTER}.mdk
	madoko --pdf -vv --odir=build $<
	cp build/${CHARTER}.pdf docs/

clean:
	${RM} -rf build 

