# Create the build container to compile
FROM rust:latest as builder
RUN USER=root cargo new --bin lonk
WORKDIR lonk

# Compile dependencies

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo build
RUN rm src/*.rs

# Compile the source
COPY ./src ./src
RUN rm ./target/release/deps/lonk*
RUN cargo build

# Execution container
FROM scratch
COPY --from=build /lonk/target/release/lonk .
CMD ["./lonk"]        