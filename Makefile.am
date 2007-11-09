SUBDIRS = lib server
AUTOMAKE_OPTIONS = no-dist-gzip dist-bzip2

package: dist
	cp wseventsink.spec /usr/src/packages/SPEC
	cp wseventsink-*.tar.gz /usr/src/packages/SOURCES
	rpmbuild -ba wseventsink.spec
