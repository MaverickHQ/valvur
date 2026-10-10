# ClusterFuzzLite's build of valvur's fuzzers (R27.4, D63c): the OSS-Fuzz Python
# builder, which carries atheris and the `compile_python_fuzzer` script, and the tree.
# v1, pinned by the digest ClusterFuzzLite's first build of this tree resolved it to
# (PR #196, 2026-10-04); the tag stays readable, and Dependabot can see it.
FROM gcr.io/oss-fuzz-base/base-builder-python:v1@sha256:88bcf57cb6507ccc95cb5fcc3afeece6278b24880ec483a17f044a154277f9d0
COPY . $SRC/valvur
WORKDIR $SRC/valvur
COPY .clusterfuzzlite/build.sh $SRC/
