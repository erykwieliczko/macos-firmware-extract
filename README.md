# macos-firmware-extract

Since macOS 27, Apple ships its restore and Recovery images as Apple Encrypted
Archives (AEA). This tool gets firmware out of them: it decrypts an image with
the key Apple publishes for it, and it fetches individual firmware files from a
restore image by byte range without downloading the whole thing. The
[Omarchy Mac installer](https://github.com/aurora-silicon/omarchy-mac) bundles
it in its installer engine as `omarchy-restore-image`.

## Commands

```sh
omarchy-restore-image INPUT_AEA INPUT_SHA256 OUTPUT_DMG
```

Decrypts an AEA image into a disk image. The input must match `INPUT_SHA256`;
it is copied to a private directory before anything reads it. The decryption
key comes from the URL in the archive's metadata, accepted only over HTTPS from
`wkms-public.apple.com` or `fcs-keys-pub-prod.cdn-apple.com`, and is unwrapped
with HPKE using the public key in that metadata. Decryption itself is done by
Apple's `/usr/bin/aea`, and `hdiutil` checks the result. macOS only.

```sh
omarchy-restore-image firmware-ranges RECIPE RECIPE_SHA256 OUTPUT_DIR
```

Fetches the byte ranges a recipe names from a restore image, decrypts the AEA
segments that hold the wanted files, checks every range and file against the
recipe's SHA-256s, and writes the files under `OUTPUT_DIR`. The recipe itself
must match `RECIPE_SHA256`. It holds offsets, sizes and digests only, no Apple
data; `testdata/j700-25G83-ranges.json` is the one for the MacBook Neo's
MT7932 Wi-Fi and Bluetooth inputs from macOS 26.6.2 (25G83). Exit status 75
means the ranges could not be fetched and the caller may download the whole
image instead.

```sh
omarchy-restore-image verify-stage1 FILE SHA256 SIZE
omarchy-restore-image capabilities
```

`verify-stage1` checks a raw Stage 1 bootloader against its digest and size;
`capabilities` lists the commands above.

## Building

```sh
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o omarchy-restore-image .
go test ./...
```

## History

The first commit imports the tool verbatim from commit
`bae75007c3b6247e5a14a2f653c15693092a7841` of the Omarchy Mac installer, the
revision the bundled binary records in its Go build information. The second
removes the commands only the development installer used (`aurora-tar`,
`verify-catalog` and `catalog-details`).

## License

MIT, as each source file states.
