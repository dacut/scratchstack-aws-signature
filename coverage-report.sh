#!/bin/bash -ex
ROOT=$(cd $(dirname $0); pwd)
llvm-cov report -Xdemangler=rustfilt \
    -use-color \
    -ignore-filename-regex='/.cargo/|.*thread/local.rs' \
    -instr-profile=$ROOT/base-library/scratchstack-aws-signature.profdata \
    $ROOT/target/coverage/debug/deps/scratchstack_aws_signature-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]

llvm-cov report -Xdemangler=rustfilt \
    -use-color \
    -ignore-filename-regex='/.cargo/|.*thread/local.rs|base-library/' \
    -instr-profile=$ROOT/hyper-integration/scratchstack-aws-signature-hyper.profdata \
    $ROOT/target/coverage/debug/deps/scratchstack_aws_signature_hyper-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]
