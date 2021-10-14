# TII TLS C

TLS Client

# Building

The TLS library is designed to support crypto agility by chaning cryptographic providers. There are three cryptographic providers one can choose from.

## Miracl

```
./scripts/build.sh -1
```

## Miracl + LibSodium

```
./scripts/build.sh -2
```

## Custom Crypto Library

```
./scripts/build.sh -3
```