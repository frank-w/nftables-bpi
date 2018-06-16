if BUILD_MAN
man_MANS = nft.8 libnftables-json.5 libnftables.3
endif

if BUILD_PDF
pdf_DATA = nft.pdf libnftables-json.pdf libnftables.pdf
endif

pdfdir=${docdir}/pdf

.xml.pdf:
	${AM_V_GEN}dblatex -q -t pdf -o $@ $<

.xml.8:
	${AM_V_GEN}${DB2MAN} --xinclude $<

.adoc.pdf:
	a2x --doctype manpage --format pdf $<

.adoc.3:
	a2x --doctype manpage --format manpage $<

.adoc.5:
	a2x --doctype manpage --format manpage $<

EXTRA_DIST = nft.xml libnftables-json.adoc libnftables.adoc

CLEANFILES = \
	nft.pdf nft.8 \
	libnftables-json.pdf libnftables-json.5 \
	libnftables.pdf libnftables.3 \
	*~
