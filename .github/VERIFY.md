# Verify RakomiSDK releases

A release of RakomiSDK is a tag `X.Y.Z` on this repository. Swift Package Manager resolves the package
from that tag. The GitHub Release of the tag carries:

- `rakomi-swift-X.Y.Z.tar.gz`: `git archive` of the tag commit;
- `rakomi-swift-X.Y.Z.cdx.json`: the CycloneDX SBOM (`sbom.cdx.json`) of the tag commit;
- `*.sigstore.json`: Sigstore bundles for both files, signed keylessly by the `release.yml` workflow of
  this repository and recorded in the public Rekor transparency log;
- `SHA256SUMS`.

The archive also carries GitHub artifact attestations (build provenance and SBOM).

## What this proves, and what it does not

The signatures and attestations prove that the files were produced by the `release.yml` workflow of this
repository for that tag. They say nothing about the quality of the code. A tag is created only for the
head of a merged pull request, and the release workflow refuses a tag that is not.

## Commands

```sh
TAG=X.Y.Z
gh release download "$TAG" --repo rakomidev/rakomi-swift

cosign verify-blob --bundle "rakomi-swift-$TAG.tar.gz.sigstore.json" \
  --certificate-identity "https://github.com/rakomidev/rakomi-swift/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "rakomi-swift-$TAG.tar.gz"

gh attestation verify "rakomi-swift-$TAG.tar.gz" --repo rakomidev/rakomi-swift

# The archive holds the files of the tag:
git clone https://github.com/rakomidev/rakomi-swift
git -C rakomi-swift checkout "$TAG"
mkdir unpacked && tar -xzf "rakomi-swift-$TAG.tar.gz" -C unpacked
diff -r --exclude=.git rakomi-swift "unpacked/rakomi-swift-$TAG"
```

## Report a vulnerability

See `SECURITY.md`.
