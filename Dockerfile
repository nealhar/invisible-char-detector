# --- Stage 1: Build the Rust binary ---
FROM rust:1.80-slim-bookworm AS builder

WORKDIR /app
COPY . .

# Build for release to optimize for speed and size
RUN cargo build --release

# --- Stage 2: Create the runner image ---
FROM debian:bookworm-slim

# Install basic certificates to avoid issues with HTTPS/SSL if needed
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/invisible-char-detector /usr/local/bin/invisible-char-detector

# Set the binary as the entrypoint
# GitHub Actions will pass the "args" from action.yml directly to this
ENTRYPOINT ["invisible-char-detector"]