#!/usr/bin/zsh

targets=(
  "x86_64-linux-android x86_64"
  "aarch64-linux-android arm64-v8a"
)

export CROSS_CONTAINER_ENGINE="podman"

rm -r jniLibs; mkdir jniLibs

cargo update

for target in ${targets[@]}; do
  read tuple abi <<< $target
  echo "building $tuple"
  cross build --release --target $tuple

  output=jniLibs/$abi
  echo $output
  mkdir $output
  cp target/$tuple/release/liblibmcqfw_rust.so $output/libmcqfw.so
done
