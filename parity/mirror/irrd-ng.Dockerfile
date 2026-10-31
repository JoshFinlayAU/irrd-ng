# The static irrd-ng binary on its own: no libc, no resolver library, no
# CA bundle. Everything it needs is in the binary.
FROM scratch
COPY irrd-ng /irrd-ng
ENTRYPOINT ["/irrd-ng"]
