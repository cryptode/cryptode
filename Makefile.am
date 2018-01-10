AUTOMAKE_OPTIONS = foreign
SUBDIRS = etc platforms src tests

EXTRA_DIST = upload_release.sh.in

release-upload: upload_release.sh
	chmod 755 upload_release.sh && ./upload_release.sh
