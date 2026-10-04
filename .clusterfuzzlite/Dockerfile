# ClusterFuzzLite's build of valvur's fuzzers (R27.4, D63c): the OSS-Fuzz Python
# builder, which carries atheris and the `compile_python_fuzzer` script, and the tree.
# v1, pinned by the digest ClusterFuzzLite's first build of this tree resolved it to
# (PR #196, 2026-10-04); the tag stays readable, and Dependabot can see it.
FROM gcr.io/oss-fuzz-base/base-builder-python:v1@sha256:855167924712ac98dedabf0ae44071caccbb0130bb0544ea06522b1f82288371
COPY . $SRC/valvur
WORKDIR $SRC/valvur
COPY .clusterfuzzlite/build.sh $SRC/
