FROM rust:1.94-slim AS backend-build

WORKDIR /srv/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && cargo fetch --locked \
    && rm -rf src

COPY src ./src

RUN cargo build --locked --release

FROM node:24-slim AS frontend-build

WORKDIR /srv/frontend

COPY frontend/package.json frontend/package-lock.json ./

RUN npm ci

COPY frontend ./

RUN npm run build

#FROM debian:trixie-slim AS runtime

#RUN apt-get update \
#    && apt-get install -y --no-install-recommends ca-certificates \
#    && rm -rf /var/lib/apt/lists/*

#RUN groupadd --system rvfa \
#    && useradd --system --gid rvfa --uid 1000 --home /srv/app --create-home rvfa

FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
COPY --from=backend-build /lib/*/libz.so.1 /lib/
COPY --from=backend-build /lib/*/libzstd.so.1 /lib/

WORKDIR /srv/app

COPY --from=backend-build /srv/app/target/release/rusty-valkey-forward-auth /usr/local/bin/rusty-valkey-forward-auth
COPY --from=frontend-build /srv/frontend/dist ./frontend/dist

ENV STATIC_DIR=/srv/app/frontend/dist \
    PORT=8080

EXPOSE 8080

#USER rvfa

#CMD ["rusty-valkey-forward-auth"]
ENTRYPOINT ["rusty-valkey-forward-auth"]
