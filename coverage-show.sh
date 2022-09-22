#!/bin/bash -ex
ROOT=$(cd $(dirname $0); pwd)
mkdir -p $ROOT/coverage-html
find $ROOT/coverage-html -type f -delete
llvm-cov show \
    -format=html \
    -ignore-filename-regex='/.cargo/|.*thread/local.rs' \
    -Xdemangler=rustfilt \
    -output-dir=$ROOT/coverage-html/scratchstack-aws-signature \
    -instr-profile=$ROOT/base-library/scratchstack-aws-signature.profdata \
    $ROOT/target/coverage/debug/deps/scratchstack_aws_signature-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]
llvm-cov show \
    -format=html \
    -ignore-filename-regex='/.cargo/|.*thread/local.rs|base-library/' \
    -Xdemangler=rustfilt \
    -output-dir=$ROOT/coverage-html/scratchstack-aws-signature-hyper \
    -instr-profile=$ROOT/hyper-integration/scratchstack-aws-signature-hyper.profdata \
    $ROOT/target/coverage/debug/deps/scratchstack_aws_signature_hyper-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]

case $(uname -s) in
    Darwin )
        open coverage-html/scratchstack-aws-signature/index.html
        open coverage-html/scratchstack-aws-signature-hyper/index.html
        ;;
    Linux )
        xdg-open coverage-html/scratchstack-aws-signature/index.html
        xdg-open coverage-html/scratchstack-aws-signature-hyper/index.html
        ;;
esac
