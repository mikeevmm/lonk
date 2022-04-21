# Prepare container
FROM rust:slim-buster
RUN USER=root cargo new --bin lonk
WORKDIR /lonk

# Compile dependencies

COPY ./Cargo.lock /lonk/Cargo.lock
COPY ./Cargo.toml /lonk/Cargo.toml

ARG PROFILE

RUN cargo build
RUN rm src/*.rs

# Compile the source
COPY ./src ./src
RUN rm ./target/${PROFILE:-release}/deps/lonk*
RUN cargo build
RUN cp /lonk/target/${PROFILE:-debug}/lonk /bin/lonk

# Execution container
FROM rust:latest
ARG PROFILE
COPY --from=builder /lonk/target/${PROFILE:-release}/lonk .
CMD ["./lonk"]        
