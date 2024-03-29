# Prepare container
FROM rust:latest as builder
RUN USER=root cargo new --bin lonk
WORKDIR /lonk

# Compile dependencies

COPY ./Cargo.lock /lonk/Cargo.lock
COPY ./Cargo.toml /lonk/Cargo.toml

ARG PROFILE

RUN [ "${PROFILE}" = "debug" ] \
        && cargo build \
        || cargo build --release 
RUN rm src/*.rs

# Compile the source
COPY ./src ./src
RUN rm -f ./target/${PROFILE:-release}/deps/lonk*
RUN [ "${PROFILE}" = "debug" ] \
        && cargo build \
        || cargo build --release 

# Execution container
FROM rust:slim
WORKDIR /
ARG PROFILE
COPY --from=builder /lonk/target/${PROFILE:-release}/lonk /bin/lonk
CMD ["/bin/lonk"]        
