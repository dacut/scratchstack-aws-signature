#!/bin/bash
llvm-cov report -Xdemangler=rustfilt \
    -use-color \
    -ignore-filename-regex='/.cargo/|.*thread/local.rs' \
    -instr-profile=scratchstack-aws-signature.profdata \
    target/debug/deps/scratchstack_aws_signature-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    -object target/debug/deps/scratchstack_aws_signature_hyper-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]
