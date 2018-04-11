
INT=INT
REPORT=telemetry_report

all: ${INT}.pdf ${REPORT}.pdf

${INT}.pdf: ${INT}.mdk
	madoko --pdf -vv --png --odir=build $<
	cp build/${INT}.pdf ../../docs

${INT}.html: ${INT}.mdk
	madoko -vv --odir=build $<

${INT}.pdf: p4.json
${INT}.html: p4.json

${REPORT}.pdf: ${REPORT}.mdk
	madoko --pdf -vv --odir=build $<
	cp build/${REPORT}.pdf ../../docs

clean:
	${RM} -rf build

