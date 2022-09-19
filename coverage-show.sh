#!/bin/bash
mkdir -p coverage-html
find coverage-html -type f -delete
llvm-cov show \
    -format=html \
    -ignore-filename-regex='/.cargo/|.*thread/local.rs' \
    -Xdemangler=rustfilt \
    -output-dir=coverage-html \
    -instr-profile=scratchstack-aws-signature.profdata \
    target/debug/deps/scratchstack_aws_signature-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    -object target/debug/deps/scratchstack_aws_signature_hyper-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]

case $(uname -s) in
    Darwin )
        open coverage-html/index.html
        ;;
    Linux )
        xdg-open coverage-html/index.html
        ;;
esac
