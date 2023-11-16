FROM rustlang/rust:nightly-bullseye-slim
WORKDIR /opt/build
COPY . .
RUN cargo build --release
WORKDIR /opt/mcpot
RUN cp /opt/build/target/release/mcpot .
RUN cp /opt/build/config.toml .
ENTRYPOINT ["/opt/mcpot/mcpot"]
