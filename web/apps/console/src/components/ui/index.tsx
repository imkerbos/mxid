// Re-export everything from @mxid/shared/ui so existing imports keep
// working while the canonical source moves to the shared package
// (portal needs the same primitives — single source of truth).
//
// eslint-disable-next-line react-refresh/only-export-components -- pure re-export shim
export * from '@mxid/shared/ui'
