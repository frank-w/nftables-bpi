if BUILD_MAN
man_MANS = nft.8 libnftables-json.5 libnftables.3
endif

ASCIIDOC_MAIN = nft.txt
ASCIIDOC_INCLUDES = \
       data-types.txt \
       payload-expression.txt \
       primary-expression.txt \
       stateful-objects.txt \
       statements.txt
ASCIIDOCS = ${ASCIIDOC_MAIN} ${ASCIIDOC_INCLUDES}

.txt.8: ${ASCIIDOCS}
	${AM_V_GEN}${A2X} --doctype manpage --format manpage -D ${builddir} $<

.adoc.3:
	a2x --doctype manpage --format manpage -D ${builddir} $<

.adoc.5:
	a2x --doctype manpage --format manpage -D ${builddir} $<

EXTRA_DIST = ${ASCIIDOCS} libnftables-json.adoc libnftables.adoc

CLEANFILES = \
	nft.8 \
	libnftables-json.5 \
	libnftables.3 \
	*~
