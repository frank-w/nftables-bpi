if BUILD_MAN
man_MANS = nft.8 libnftables-json.5 libnftables.3
endif

if BUILD_PDF
pdf_DATA = nft.pdf libnftables-json.pdf libnftables.pdf
endif

ASCIIDOC_MAIN = nft.txt
ASCIIDOC_INCLUDES = \
       data-types.txt \
       payload-expression.txt \
       primary-expression.txt \
       stateful-objects.txt \
       statements.txt
ASCIIDOCS = ${ASCIIDOC_MAIN} ${ASCIIDOC_INCLUDES}

pdfdir=${docdir}/pdf

nft.8: ${ASCIIDOCS}
	${AM_V_GEN}${A2X} --doctype manpage --format manpage ${ASCIIDOC_MAIN}

nft.pdf: ${ASCIIDOCS}
	${AM_V_GEN}${A2X} --doctype manpage --format pdf ${ASCIIDOC_MAIN}

.adoc.pdf:
	a2x --doctype manpage --format pdf -D ${builddir} $<

.adoc.3:
	a2x --doctype manpage --format manpage -D ${builddir} $<

.adoc.5:
	a2x --doctype manpage --format manpage -D ${builddir} $<

EXTRA_DIST = ${ASCIIDOCS} libnftables-json.adoc libnftables.adoc

CLEANFILES = \
	nft.xml nft.pdf nft.8 \
	libnftables-json.pdf libnftables-json.5 \
	libnftables.pdf libnftables.3 \
	*~
