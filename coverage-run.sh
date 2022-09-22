#!/bin/bash -ex
CLEAN=1
ROOT=$(cd $(dirname $0); pwd)

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-clean)
            CLEAN=0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

rm -f *.profdata *.profraw base-library/*.profraw base-library/*.profdata hyper/*.profraw hyper/*.profdata

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0"
if [[ $CLEAN -ne 0 ]]; then
    cargo clean --target-dir "$ROOT/target/coverage"
    (cd $ROOT/base-library && \
        LLVM_PROFILE_FILE="$ROOT/base-library/scratchstack-aws-signature-%m.profraw" cargo build --target-dir "$ROOT/target/coverage")
    (cd $ROOT/hyper-integration && \
        LLVM_PROFILE_FILE="$ROOT/hyper-integration/scratchstack-aws-signature-hyper-%m.profraw" cargo build --target-dir "$ROOT/target/coverage")
fi

(cd $ROOT/base-library && \
    LLVM_PROFILE_FILE="$ROOT/base-library/scratchstack-aws-signature-%m.profraw" RUST_LOG=trace cargo test --target-dir "$ROOT/target/coverage")
(cd $ROOT/hyper-integration && \
    LLVM_PROFILE_FILE="$ROOT/hyper-integration/scratchstack-aws-signature-hyper-%m.profraw" RUST_LOG=trace cargo test --target-dir "$ROOT/target/coverage")
llvm-profdata merge -sparse $ROOT/base-library/scratchstack-aws-signature-*.profraw -o base-library/scratchstack-aws-signature.profdata
llvm-profdata merge -sparse $ROOT/hyper-integration/scratchstack-aws-signature-hyper-*.profraw -o hyper-integration/scratchstack-aws-signature-hyper.profdata
llvm-cov export -format lcov -Xdemangler=rustfilt -ignore-filename-regex='/.cargo/|.*thread/local.rs' \
    -instr-profile=base-library/scratchstack-aws-signature.profdata \
    target/coverage/debug/deps/scratchstack_aws_signature-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    > "$ROOT/scratchstack-aws-signature.lcov"
llvm-cov export -format lcov -Xdemangler=rustfilt -ignore-filename-regex='/.cargo/|.*thread/local.rs' \
    -instr-profile=hyper-integration/scratchstack-aws-signature-hyper.profdata \
    target/coverage/debug/deps/scratchstack_aws_signature_hyper-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    > "$ROOT/scratchstack-aws-signature-hyper.lcov"
"$ROOT/coverage-fixup.py" "$ROOT/scratchstack-aws-signature.lcov"
"$ROOT/coverage-fixup.py" "$ROOT/scratchstack-aws-signature-hyper.lcov"
