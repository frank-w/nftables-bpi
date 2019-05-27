EXTRA_DIST = setup.py __init__.py nftables.py schema.json

if HAVE_PYTHON

all-local:
	cd $(srcdir) && \
		$(PYTHON_BIN) setup.py build --build-base $(abs_builddir)

install-exec-local:
	cd $(srcdir) && \
		$(PYTHON_BIN) setup.py build --build-base $(abs_builddir) \
		install --prefix $(DESTDIR)$(prefix)

uninstall-local:
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/site-packages/nftables
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/dist-packages/nftables
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/site-packages/nftables-[0-9]*.egg-info
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/dist-packages/nftables-[0-9]*.egg-info
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/site-packages/nftables-[0-9]*.egg
	rm -rf $(DESTDIR)$(prefix)/lib*/python*/dist-packages/nftables-[0-9]*.egg

clean-local:
	cd $(srcdir) && \
		$(PYTHON_BIN) setup.py clean \
		--build-base $(abs_builddir)
	rm -rf scripts-* lib* build dist bdist.* nftables.egg-info
	find . -name \*.pyc -print0 | xargs -0 rm -f

distclean-local:
	rm -f version
endif
