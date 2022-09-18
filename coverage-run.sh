#!/bin/bash
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

rm -f *.profdata *.profraw

export CARGO_INCREMENTAL=0
export LLVM_PROFILE_FILE="$ROOT/scratchstack-core-%m.profraw"
export RUSTFLAGS="-Cinstrument-coverage"
if [[ $CLEAN -ne 0 ]]; then
    cargo clean
    cargo build
fi
cargo test
llvm-profdata merge -sparse scratchstack-core-*.profraw -o scratchstack-core.profdata
llvm-cov export -format lcov -Xdemangler=rustfilt -ignore-filename-regex='/.cargo/registry|.*thread/local.rs' \
    -instr-profile=scratchstack-core.profdata \
    target/debug/deps/scratchstack_arn-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    -object target/debug/deps/scratchstack_aws_principal-[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9] \
    > "$ROOT/lcov.info"
"$ROOT/coverage-fixup.py" "$ROOT/lcov.info"
