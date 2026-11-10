// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! Size and resource limits (§13). Every limit has a fixed error code in the
//! specification; module owners use these constants so the numbers appear in
//! exactly one place.

/// `MAX_RECORD_BYTES`: one record file or standalone record (1 MiB).
pub const MAX_RECORD_BYTES: usize = 1_048_576;
/// `MAX_MANIFEST_BYTES`: `manifest.json` and `previous/manifest.json` (4 MiB).
pub const MAX_MANIFEST_BYTES: usize = 4_194_304;
/// `MAX_SIGFILE_BYTES`: `signatures/manifest.sig.json` (1 MiB).
pub const MAX_SIGFILE_BYTES: usize = 1_048_576;
/// `MAX_TIMESTAMP_BYTES`: one `.tsr` file (1 MiB).
pub const MAX_TIMESTAMP_BYTES: usize = 1_048_576;
/// `MAX_RECORDS`: `manifest.records` entries.
pub const MAX_RECORDS: usize = 100_000;
/// `MAX_CONTAINER_ENTRIES`: all zip entries, or all files in a directory.
pub const MAX_CONTAINER_ENTRIES: usize = 200_000;
/// `MAX_CONTAINER_UNCOMPRESSED_BYTES`: total uncompressed bytes (1 GiB).
pub const MAX_CONTAINER_UNCOMPRESSED_BYTES: u64 = 1_073_741_824;
/// `MAX_BLOB_BYTES`: one blob (1 GiB).
pub const MAX_BLOB_BYTES: u64 = 1_073_741_824;
/// `MAX_BLOBS`: `manifest.blobs` entries.
pub const MAX_BLOBS: usize = 10_000;
/// `MAX_REFS`: `refs` entries.
pub const MAX_REFS: usize = 256;
/// `MAX_SIGS`: `sigs` entries.
pub const MAX_SIGS: usize = 16;
/// `MAX_HINTS`: one reference's `hints` entries.
pub const MAX_HINTS: usize = 8;
/// `MAX_SIG_VALUE_BYTES`: decoded bytes of a non-ed25519 signature value.
pub const MAX_SIG_VALUE_BYTES: usize = 2_048;
/// `MAX_GRANT_CHAIN`: delegated grant chain depth.
pub const MAX_GRANT_CHAIN: usize = 8;
