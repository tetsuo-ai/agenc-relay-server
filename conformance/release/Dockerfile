FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

# The native release build image. scripts/build-release-image.py copies the
# host's pinned Rust 1.98.0 sysroot into the build context, so the image
# carries the exact compiler the build record names and needs no network for
# the toolchain. The package list is recorded after installation; the image
# ID and the Dockerfile digest are recorded beside it.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential python3 && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain /opt/rust
ENV PATH="/opt/rust/bin:${PATH}"
RUN rustc --version && cargo --version && cc --version && ld --version && ldd --version \
    && python3 --version && dpkg-query -W > /opt/release-packages.txt
