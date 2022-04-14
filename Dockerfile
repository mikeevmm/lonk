# Prepare container
FROM rust:slim-buster
RUN USER=root cargo new --bin lonk
WORKDIR lonk

# Compile dependencies

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo build
RUN rm src/*.rs

# Compile the source
COPY ./src ./src
RUN cargo build
RUN cp /lonk/target/${PROFILE:-debug}/lonk .

CMD ["./lonk"]