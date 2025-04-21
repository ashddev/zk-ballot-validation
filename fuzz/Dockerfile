FROM rustlang/rust:nightly

RUN apt update && apt install -y libclang-dev

WORKDIR /app

COPY . .

RUN cargo install cargo-fuzz
