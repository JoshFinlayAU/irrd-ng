# IRRd v4 reference server for the parity harness.
#
# Built from the pinned source in vendor/irrd-v4, with every runtime
# dependency installed from v4's own poetry.lock with hash checking, so the
# image is exactly the baseline release and nothing floats. Python matches
# the production reference server (3.13).
FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir poetry==2.2.1 poetry-plugin-export==1.9.0
WORKDIR /src
COPY vendor/irrd-v4/ ./
RUN poetry export --only main -f requirements.txt -o /requirements.txt \
 && python -m venv /opt/irrd \
 && /opt/irrd/bin/pip install --no-cache-dir --require-hashes -r /requirements.txt \
 && /opt/irrd/bin/pip install --no-cache-dir --no-deps .

FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
RUN apt-get update \
 && apt-get install -y --no-install-recommends gnupg postgresql-client \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --home-dir /var/lib/irrd irrd \
 && install -d -o irrd -g irrd /run/irrd /var/lib/irrd/gnupg /var/lib/irrd/nrtm4
COPY --from=build /opt/irrd /opt/irrd
COPY parity/v4/entrypoint.sh /entrypoint.sh
ENV PATH=/opt/irrd/bin:$PATH
USER irrd
EXPOSE 8043 8080
ENTRYPOINT ["/entrypoint.sh"]
