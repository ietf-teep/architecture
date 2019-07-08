FN := $(shell grep 'docname: draft-ietf-teep-architecture' draft-ietf-teep-architecture.md | awk '{print $$2}')

$(FN).txt: $(FN).xml
	xml2rfc $(FN).xml

$(FN).xml: draft-ietf-teep-architecture.md
	kramdown-rfc2629 draft-ietf-teep-architecture.md > $(FN).xml

