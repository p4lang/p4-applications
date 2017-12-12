
INT=INT

all: ${INT}.pdf 

${INT}.pdf: ${INT}.mdk
	madoko --pdf -vv --odir=build $<
	cp build/${INT}.pdf ../../docs

${INT}.html: ${INT}.mdk
	madoko -vv --odir=build $<

${INT}.pdf: p4.json
${INT}.html: p4.json

clean:
	${RM} -rf build

