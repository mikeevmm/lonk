# Prepare container
FROM rust:slim-buster
RUN USER=root cargo new --bin lonk
WORKDIR /lonk

# Compile dependencies

COPY ./Cargo.lock /lonk/Cargo.lock
COPY ./Cargo.toml /lonk/Cargo.toml

RUN cargo build
RUN rm /lonk/src/*.rs

# Compile the source
COPY ./src /lonk/src
RUN rm /lonk/target/${PROFILE:-debug}/deps/lonk*
RUN cargo build
RUN cp /lonk/target/${PROFILE:-debug}/lonk /bin/lonk

WORKDIR /bin
CMD ["./lonk"]