FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates cmake gcc g++ gettext git libcurl4-openssl-dev \
    libgcrypt20-dev libglib2.0-dev libgnutls28-dev libncurses-dev \
    libssl-dev libutf8proc-dev libzstd-dev make meson ninja-build \
    pkg-config python3 zlib1g-dev && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain /opt/rust
ENV PATH="/opt/rust/bin:${PATH}"
COPY weechat /clients/weechat
COPY irssi /clients/irssi

RUN cmake -S /clients/weechat -B /clients/weechat-build \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/clients \
    -DENABLE_NCURSES=OFF -DENABLE_HEADLESS=ON -DENABLE_SCRIPTS=OFF \
    -DENABLE_SCRIPT=OFF -DENABLE_SPELL=OFF -DENABLE_RELAY=OFF \
    -DENABLE_XFER=OFF -DENABLE_EXEC=OFF -DENABLE_CJSON=OFF \
    -DENABLE_TESTS=OFF -DENABLE_DOC=OFF -DENABLE_MAN=OFF \
    && cmake --build /clients/weechat-build --parallel 8 \
    && cmake --install /clients/weechat-build

RUN meson setup /clients/irssi-build /clients/irssi \
    --buildtype=release --prefix=/opt/clients -Dwith-perl=no -Dwith-otr=no \
    -Dwith-bot=no -Dwith-proxy=no -Dwith-fuzzer=no \
    && meson compile -C /clients/irssi-build -j 8 \
    && meson install -C /clients/irssi-build

ENV PATH="/opt/clients/bin:${PATH}"
RUN rustc --version && weechat-headless --version && irssi --version \
    && dpkg-query -W > /opt/qualification-packages.txt

COPY chutney /clients/chutney
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3-venv tor tcpdump && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/tor-tools \
    && /opt/tor-tools/bin/pip install --no-cache-dir /clients/chutney \
    && /opt/tor-tools/bin/pip freeze > /opt/tor-python-packages.txt \
    && tor --version && tcpdump --version \
    && dpkg-query -W > /opt/qualification-packages.txt
