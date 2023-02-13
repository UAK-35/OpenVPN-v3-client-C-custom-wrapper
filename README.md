# OpenVPN Client C++ custom Wrapper

## Version 0.0.0.1

### Installation on Ubuntu

Initialize git submodule first

```bash
cd OvpncltWrapper

export O3=$(pwd)
export DEP_DIR=$O3/deps
export DL=$O3/dl
export NO_WIPE=1
export MTLS=1

mkdir $DEP_DIR && mkdir $DL
echo "*" > $DEP_DIR/.gitignore
echo "*" > $DL/.gitignore

cd core/scripts/linux/
./build-all
cd $DEP_DIR
rm -r asio-asio* lz4-* mbedtls-* xxHash-*
```

Then use "Unix Makefiles" as CMake generator

