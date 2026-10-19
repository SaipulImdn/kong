# Ceriku Kong source fork

This is a full source fork of Kong Gateway OSS, pinned to upstream tag `3.9.3` on branch `ceriku/oss-3.9.3`. It keeps Kong's source, build system, packages, and Apache-2.0 license in this repository so Ceriku can maintain and change the gateway itself.

Ceriku-specific code lives in:

- `kong/plugins/ceriku-auth/`: request signature checks, Redis session resolution and rate limits, identity signing, CORS, and safe request logs.
- `build/ceriku/kong.yml`: DB-less routes and plugin configuration.
- `Containerfile.ceriku`: builds Kong's Debian package from this checkout, then assembles the Ceriku image and checks the declarative config. Build it with Podman using `podman build -f Containerfile.ceriku`.

Kong-generated HTTP errors use the Ceriku JSON envelope `{response_code, response_desc, response_data}`. The HTTP status remains the transport status; upstream service response bodies are passed through unchanged.

To build and publish `saipulimdnn/ceriku-kong`, run the **Publish Ceriku Kong OSS** workflow in `SaipulImdn/axe-gateway`, selecting this branch and an image tag. The workflow builds this repository's source; it does not layer custom files over a prebuilt Kong image.

The upstream Kong remote is retained as `upstream`; updates should start from a reviewed Kong OSS release tag and be merged into this branch before publishing a new image.
