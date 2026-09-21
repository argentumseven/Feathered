# Feathered distribution notice

Feathered-authored source code is licensed under the MIT License in `LICENSE`.

Production builds also contain third-party software, including the CPython
runtime and standard library, python-zstandard, PyYAML, the PyInstaller bootloader and
runtime components, and the staged GnuPG `gpgv` verifier with its runtime
libraries. Those components are not relicensed by Feathered's MIT License and
remain subject to their respective upstream licenses and notices.

Anyone redistributing a compiled Feathered release is responsible for retaining
or supplying the third-party license material, notices, and source-code offers
required by those upstream licenses. `requirements-build.lock` records the
Python build dependency versions used by the production gate; the staged GnuPG
version is recorded in `dist/gnupg/VERIFIER-VERSION.txt` during a release build.
