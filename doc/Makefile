DOCS=$(wildcard *.rst)
HTML=$(patsubst %.rst,%.html,$(DOCS))
RST2HTML=rst2html

all: $(HTML)
	@echo $(HTML)

%.html: %.rst
	$(RST2HTML) $< $@

clean:
	rm -f $(HTML)
