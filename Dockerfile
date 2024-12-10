# SPDX-License-Identifier: Apache-2.0

FROM rust:latest as builder

WORKDIR /usr/src/tee-kms
COPY . .

RUN apt-get update && apt-get install -y protobuf-compiler

# Build and Install RESTful attestation-service
RUN cargo install --path . --bin tee-kms --locked

FROM ubuntu:22.04

COPY --from=builder /usr/local/cargo/bin/tee-kms /usr/local/bin/tee-kms

CMD ["tee-kms", "-c", "/etc/tee-kms.toml"]

VOLUME ["/etc/tee-kms.toml"]

EXPOSE 9991 9992