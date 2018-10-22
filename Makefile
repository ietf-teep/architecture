draft-ietf-teep-architecture.txt: draft-ietf-teep-architecture.xml
	xml2rfc draft-ietf-teep-architecture.xml

draft-ietf-teep-architecture.xml: draft-ietf-teep-architecture.md
	kramdown-rfc2629 draft-ietf-teep-architecture.md > draft-ietf-teep-architecture.xml
