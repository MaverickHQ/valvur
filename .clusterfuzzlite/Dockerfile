# ClusterFuzzLite's build of valvur's fuzzers (R27.4, D63c): the OSS-Fuzz Python
# builder, which carries atheris and the `compile_python_fuzzer` script, and the tree.
FROM gcr.io/oss-fuzz-base/base-builder-python:v1
COPY . $SRC/valvur
WORKDIR $SRC/valvur
COPY .clusterfuzzlite/build.sh $SRC/
