// SPDX-License-Identifier: Apache-2.0

fn main() {
    tonic_build::configure()
        .build_server(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(&["./protos/api.proto"], &["./protos"])
        .expect("Generate grpc protocol code failed.");
}
