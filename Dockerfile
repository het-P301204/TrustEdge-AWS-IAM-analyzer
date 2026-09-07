# TrustEdge - AWS inbound trust boundary analyzer
#
# The image is deliberately boring: a slim Python base, the package, and
# nothing else. TrustEdge has no runtime dependencies and makes no network
# calls, so the container needs no network at all:
#
#   docker run --rm --network none -v "$PWD:/work" -w /work trustedge \
#     analyze --input fixtures/sample-account.json --output reports/report.md
#
# Run it with --network none when analysing a real export. There is nothing in
# the analyser that needs egress, and removing it removes the question.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="TrustEdge" \
      org.opencontainers.image.description="AWS inbound trust boundary analyzer: grades who outside an account can become an identity inside it, ranked by exposure x blast radius." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/hetpatel/trustedge"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy only what the package needs, so an edit to the docs does not invalidate
# the install layer.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN python -m pip install --no-cache-dir . \
    && python -c "import trustedge; print('trustedge', trustedge.__version__)"

# Fixtures and docs are useful inside the image for a quick demo, and are
# copied after the install so they do not bust the layer cache.
COPY fixtures/ ./fixtures/
COPY docs/ ./docs/
COPY examples/ ./examples/

# An IAM export is sensitive and this tool never needs privilege. Run as an
# unprivileged user, and make /work the default place to mount host files.
#
# On Linux, writing a report into a bind-mounted host directory needs the
# container uid to match yours, or the write is denied:
#
#   docker run --rm --network none --user "$(id -u):$(id -g)" \
#     -v "$PWD:/work" -w /work trustedge analyze -i export.json -o out.md
#
# Docker Desktop on macOS and Windows handles this for you.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 trustedge \
    && mkdir -p /work \
    && chown trustedge:trustedge /work

USER trustedge
WORKDIR /work

# For `docker compose up`, which runs the local viewer. The health check lives
# in docker-compose.yml rather than here: the default use of this image is a
# one-shot `analyze`, and a health check for a server would be meaningless for
# a container that runs once and exits.
EXPOSE 8765

ENTRYPOINT ["trustedge"]
CMD ["--help"]
