# need to use manylinux2010 (not manylinux1) to deal with vsyscall issue:
# https://www.python.org/dev/peps/pep-0571/#compatibility-with-kernels-that-lack-vsyscall
FROM quay.io/pypa/manylinux2010_x86_64

ENV PATH /root/.cargo/bin:/usr/local/bin/:$PATH
# Add all supported python versions
ENV PATH /opt/python/cp36-cp36m/bin/:/opt/python/cp37-cp37m/bin/:/opt/python/cp38-cp38/bin/:/opt/python/cp39-cp39/bin/:$PATH
# Otherwise `cargo new` errors
ENV USER root

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && rustup default stable \
    && python3 -m pip install --no-cache-dir cffi \
    && mkdir /io

RUN /opt/python/cp38-cp38/bin/python -m pip install --upgrade pip setuptools maturin

# rust cmake library needs cmake 3+
# manylinux/centos6 has cmake 2.8
RUN cd /tmp \
    && curl https://cmake.org/files/v3.12/cmake-3.12.3.tar.gz > cmake-3.12.3.tar.gz \
    && tar zxvf cmake-3.* > /dev/null \
    && cd cmake-3.* \
    && ./bootstrap --prefix=/usr/local \
    && make -j3 \
    && make install \
    && rm -rf /tmp/*

ENTRYPOINT ["/opt/python/cp38-cp38/bin/maturin"]
