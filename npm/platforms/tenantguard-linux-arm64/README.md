# tenantguard-linux-arm64

This package contains the prebuilt TenantGuard binary for Linux on arm64.

TenantGuard is a tenant-isolation security-audit CLI for self-hosted multi-tenant AI-agent platforms. This platform package only ships the compiled binary for one architecture; it has no CLI logic of its own.

## Do not install this directly

Install the main `tenantguard` npm package instead:

```
npm install -g tenantguard
```

npm resolves this package automatically as an optional dependency when you are on Linux arm64, so the right binary lands on your `PATH` without any extra steps.

## Documentation

Full docs, usage, and configuration: https://github.com/RudrenduPaul/TenantGuard

## License

Apache-2.0
