
INT=INT

all: build/${INT}.pdf build/${INT}.html

build/${INT}.pdf: ${INT}.mdk
	madoko --pdf -vv --odir=build $<

build/${INT}.html: ${INT}.mdk
	madoko -vv --odir=build $<

build/${INT}.pdf: p4.json
build/${INT}.html: p4.json

clean:
	${RM} -rf build

