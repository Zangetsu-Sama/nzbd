//! Authenticated encryption of database backups at rest (T104, SEC-046).
//!
//! Format `NZBDBAK` v1 (all integers big-endian), a chunked AEAD stream so a multi-gigabyte
//! snapshot is never held in memory:
//!
//! ```text
//! header (52 bytes): magic "NZBDBAK\0" | version=1 | algorithm=1 | chunk_log2=20 | flags=0
//!                    | key_id (8) | salt (32)
//! body: chunks of up to 1 MiB plaintext, each sealed with XChaCha20-Poly1305
//!       (ciphertext = plaintext + 16-byte tag)
//! ```
//!
//! * The per-file key is `HKDF-SHA256(ikm = backup key, salt = file salt, info = "nzbd backup
//!   file key v1")`, so one 32-byte key file protects any number of backups and a nonce can never
//!   repeat across files. The chunk nonce is the chunk counter (24 bytes, big-endian), unique within
//!   the file because the file key is.
//! * AAD of every chunk = the whole header plus one byte that is 1 for the last chunk. Reordering,
//!   dropping, duplicating, truncating (even at a chunk boundary), appending and header edits all
//!   fail authentication. Whether a chunk is the last is derived from end of file, never stored.
//! * `key_id` is a 64-bit keyed digest of the key. It only exists so that "wrong key file" can be
//!   told apart from "file damaged"; it is also covered by the AAD.
//! * Decryption writes to a temporary file and publishes it (fsync + rename) only after the last
//!   chunk authenticated, so a tampered backup never leaves a plausible-looking database behind.
//!
//! The key is a separate secret from the TOTP key. It is never logged, never part of an error, and
//! is zeroized on drop. Nothing here talks to the network; randomness comes from `/dev/urandom`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: [u8; 8] = *b"NZBDBAK\0";
const VERSION: u8 = 1;
const ALG_XCHACHA20POLY1305: u8 = 1;
const CHUNK_LOG2: u8 = 20;
const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const KEY_ID_LEN: usize = 8;
const SALT_LEN: usize = 32;
/// Header size in bytes.
pub const HEADER_LEN: usize = 8 + 4 + KEY_ID_LEN + SALT_LEN;
const INFO_FILE_KEY: &[u8] = b"nzbd backup file key v1\x01";
const INFO_KEY_ID: &[u8] = b"nzbd backup key id v1";

/// Why encrypting or decrypting a backup failed. No variant carries key or content bytes.
#[derive(Debug, thiserror::Error)]
pub enum BackupCryptoError {
    /// The file does not start with the encrypted-backup magic (plain database or other file).
    #[error("not an encrypted nzbd backup")]
    NotEncrypted,
    /// A format version or algorithm this build does not know.
    #[error("unsupported encrypted backup format (version {0})")]
    Unsupported(u8),
    /// The file was made with a different key.
    #[error("wrong backup encryption key (the file was sealed with another key)")]
    WrongKey,
    /// Authentication failed or the file ends early: modified, damaged or truncated.
    #[error("backup is damaged or has been tampered with (authentication failed)")]
    Tampered,
    /// The key must be exactly 32 bytes.
    #[error("backup encryption key must be exactly 32 bytes")]
    KeyLength,
    /// OS randomness unavailable.
    #[error("OS randomness unavailable")]
    Random,
    /// Filesystem error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// The 32-byte backup encryption key. Zeroized on drop, never printed.
#[derive(Clone)]
pub struct BackupKey([u8; 32]);

impl BackupKey {
    /// Copies exactly 32 bytes; any other length is refused.
    ///
    /// # Errors
    /// [`BackupCryptoError::KeyLength`].
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BackupCryptoError> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| BackupCryptoError::KeyLength)
    }

    /// Constant-time equality with another 32-byte secret (used to insist that the backup key and
    /// the TOTP key are different).
    #[must_use]
    pub fn ct_eq_bytes(&self, other: &[u8]) -> bool {
        if other.len() != self.0.len() {
            return false;
        }
        let diff = self
            .0
            .iter()
            .zip(other)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }
}

impl Drop for BackupKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupKey([REDACTED])")
    }
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], BackupCryptoError> {
    let mut m =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| BackupCryptoError::KeyLength)?;
    for p in parts {
        m.update(p);
    }
    Ok(m.finalize().into_bytes().into())
}

fn key_id(key: &BackupKey) -> Result<[u8; KEY_ID_LEN], BackupCryptoError> {
    let full = hmac(&key.0, &[INFO_KEY_ID])?;
    let mut out = [0_u8; KEY_ID_LEN];
    out.copy_from_slice(full.get(..KEY_ID_LEN).ok_or(BackupCryptoError::Tampered)?);
    Ok(out)
}

/// HKDF-SHA256 (RFC 5869) with a single output block.
fn file_key(key: &BackupKey, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, BackupCryptoError> {
    let prk = Zeroizing::new(hmac(salt, &[&key.0])?);
    Ok(Zeroizing::new(hmac(prk.as_ref(), &[INFO_FILE_KEY])?))
}

fn header(key: &BackupKey, salt: &[u8; SALT_LEN]) -> Result<[u8; HEADER_LEN], BackupCryptoError> {
    let mut h = [0_u8; HEADER_LEN];
    let mut v = Vec::with_capacity(HEADER_LEN);
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&[VERSION, ALG_XCHACHA20POLY1305, CHUNK_LOG2, 0]);
    v.extend_from_slice(&key_id(key)?);
    v.extend_from_slice(salt);
    h.copy_from_slice(&v);
    Ok(h)
}

fn nonce(counter: u64) -> XNonce {
    let mut n = [0_u8; 24];
    if let Some(tail) = n.get_mut(16..) {
        tail.copy_from_slice(&counter.to_be_bytes());
    }
    XNonce::from(n)
}

/// Reads until `buf` is full or EOF; returns the byte count.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0_usize;
    while let Some(rest) = buf.get_mut(n..).filter(|r| !r.is_empty()) {
        match r.read(rest) {
            Ok(0) => break,
            Ok(k) => n = n.saturating_add(k),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn aad(header: &[u8; HEADER_LEN], last: bool) -> [u8; HEADER_LEN + 1] {
    let mut a = [0_u8; HEADER_LEN + 1];
    if let Some(h) = a.get_mut(..HEADER_LEN) {
        h.copy_from_slice(header);
    }
    if let Some(l) = a.get_mut(HEADER_LEN) {
        *l = u8::from(last);
    }
    a
}

/// Encrypts `src` into `dst` with an explicit file salt (tests pin it; production uses
/// [`encrypt_stream`]).
fn encrypt_with_salt<R: Read, W: Write>(
    key: &BackupKey,
    salt: &[u8; SALT_LEN],
    src: &mut R,
    dst: &mut W,
) -> Result<(), BackupCryptoError> {
    let hdr = header(key, salt)?;
    let fk = file_key(key, salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(fk.as_ref()).map_err(|_| BackupCryptoError::KeyLength)?;
    dst.write_all(&hdr)?;
    let mut buf = vec![0_u8; CHUNK + 1];
    let mut have = 0_usize;
    let mut counter = 0_u64;
    loop {
        let n = read_full(src, buf.get_mut(have..).ok_or(BackupCryptoError::Tampered)?)?;
        let total = have.saturating_add(n);
        let last = total <= CHUNK;
        let take = if last { total } else { CHUNK };
        let msg = buf.get(..take).ok_or(BackupCryptoError::Tampered)?;
        let a = aad(&hdr, last);
        let ct = cipher
            .encrypt(&nonce(counter), Payload { msg, aad: &a })
            .map_err(|_| BackupCryptoError::Tampered)?;
        dst.write_all(&ct)?;
        if last {
            return Ok(());
        }
        // Keep the one lookahead byte for the next chunk.
        buf.copy_within(CHUNK..=CHUNK, 0);
        have = 1;
        counter = counter.checked_add(1).ok_or(BackupCryptoError::Tampered)?;
    }
}

/// Encrypts everything from `src` into `dst` with a fresh random salt.
///
/// # Errors
/// Randomness or I/O failure.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &BackupKey,
    src: &mut R,
    dst: &mut W,
) -> Result<(), BackupCryptoError> {
    let mut salt = [0_u8; SALT_LEN];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut salt))
        .map_err(|_| BackupCryptoError::Random)?;
    encrypt_with_salt(key, &salt, src, dst)
}

/// Decrypts and authenticates a whole stream into `dst`. `dst` may already hold data of chunks
/// that authenticated before a later failure: callers must discard it on error.
///
/// # Errors
/// [`BackupCryptoError::NotEncrypted`], [`BackupCryptoError::Unsupported`],
/// [`BackupCryptoError::WrongKey`], [`BackupCryptoError::Tampered`] or I/O failure.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &BackupKey,
    src: &mut R,
    dst: &mut W,
) -> Result<(), BackupCryptoError> {
    let mut hdr = [0_u8; HEADER_LEN];
    let got = read_full(src, &mut hdr)?;
    if got < MAGIC.len() || hdr.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(BackupCryptoError::NotEncrypted);
    }
    if got < HEADER_LEN {
        return Err(BackupCryptoError::Tampered);
    }
    let version = hdr.get(8).copied().unwrap_or(0);
    let alg = hdr.get(9).copied().unwrap_or(0);
    let log2 = hdr.get(10).copied().unwrap_or(0);
    let flags = hdr.get(11).copied().unwrap_or(1);
    if version != VERSION {
        return Err(BackupCryptoError::Unsupported(version));
    }
    if alg != ALG_XCHACHA20POLY1305 || log2 != CHUNK_LOG2 || flags != 0 {
        return Err(BackupCryptoError::Unsupported(version));
    }
    let id = hdr
        .get(12..12 + KEY_ID_LEN)
        .ok_or(BackupCryptoError::Tampered)?;
    if id != key_id(key)? {
        return Err(BackupCryptoError::WrongKey);
    }
    let salt = hdr
        .get(12 + KEY_ID_LEN..HEADER_LEN)
        .ok_or(BackupCryptoError::Tampered)?;
    let fk = file_key(key, salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(fk.as_ref()).map_err(|_| BackupCryptoError::KeyLength)?;
    let ct_max = CHUNK + TAG;
    let mut buf = vec![0_u8; ct_max + 1];
    let mut have = 0_usize;
    let mut counter = 0_u64;
    loop {
        let n = read_full(src, buf.get_mut(have..).ok_or(BackupCryptoError::Tampered)?)?;
        let total = have.saturating_add(n);
        let last = total <= ct_max;
        let take = if last { total } else { ct_max };
        if take < TAG {
            // Missing final chunk (file cut at a chunk boundary or inside the tag).
            return Err(BackupCryptoError::Tampered);
        }
        let msg = buf.get(..take).ok_or(BackupCryptoError::Tampered)?;
        let a = aad(&hdr, last);
        let pt = Zeroizing::new(
            cipher
                .decrypt(&nonce(counter), Payload { msg, aad: &a })
                .map_err(|_| BackupCryptoError::Tampered)?,
        );
        dst.write_all(&pt)?;
        if last {
            return Ok(());
        }
        buf.copy_within(ct_max..=ct_max, 0);
        have = 1;
        counter = counter.checked_add(1).ok_or(BackupCryptoError::Tampered)?;
    }
}

fn open_new_0600(p: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
}

/// Encrypts the file `src` into the new 0600 file `dst` and fsyncs it. Never overwrites.
///
/// # Errors
/// See [`encrypt_stream`]; `dst` must not exist.
pub fn encrypt_file(key: &BackupKey, src: &Path, dst: &Path) -> Result<(), BackupCryptoError> {
    let mut r = io::BufReader::new(File::open(src)?);
    let mut out = open_new_0600(dst)?;
    let res = {
        let mut w = io::BufWriter::new(&mut out);
        encrypt_stream(key, &mut r, &mut w).and_then(|()| w.flush().map_err(Into::into))
    };
    res?;
    out.sync_all()?;
    Ok(())
}

/// Decrypts the encrypted backup `src` into a new file `out` (mode 0600). The output is written to
/// a hidden temporary file next to `out`, fsynced and published without replacing anything (a hard link) only
/// after every chunk authenticated; on any error nothing is left behind. An existing `out` is never
/// replaced, not even one that appears while decrypting.
///
/// # Errors
/// See [`decrypt_stream`]; `out` must not exist. Also an error when the temporary file cannot be
/// removed after publishing (the output is then complete, but a second plaintext copy is left).
pub fn decrypt_file(key: &BackupKey, src: &Path, out: &Path) -> Result<(), BackupCryptoError> {
    if fs::symlink_metadata(out).is_ok() {
        return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
    }
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = out
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".decrypt.tmp");
    let tmp = dir.join(tmp_name);
    let mut r = io::BufReader::new(File::open(src)?);
    let mut f = open_new_0600(&tmp)?;
    let res = {
        let mut w = io::BufWriter::new(&mut f);
        decrypt_stream(key, &mut r, &mut w).and_then(|()| w.flush().map_err(Into::into))
    }
    .and_then(|()| f.sync_all().map_err(Into::into))
    .and_then(|()| publish_no_clobber(&tmp, out).map_err(Into::into));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
        return res;
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Publishes the finished `tmp` as `out` without replacing a file that appeared there: a hard link,
/// which fails when `out` exists (`rename` would silently replace it). On a filesystem without hard
/// links (vfat, exFAT, some network mounts) it falls back to `rename` after checking `out` again.
/// `tmp` is gone on success.
fn publish_no_clobber(tmp: &Path, out: &Path) -> io::Result<()> {
    match fs::hard_link(tmp, out) {
        Ok(()) => fs::remove_file(tmp),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EPERM | libc::EOPNOTSUPP | libc::ENOSYS)
            ) =>
        {
            if fs::symlink_metadata(out).is_ok() {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            fs::rename(tmp, out)
        }
        Err(e) => Err(e),
    }
}

/// True when `path` starts with the encrypted-backup magic.
#[must_use]
pub fn looks_encrypted(path: &Path) -> bool {
    let mut b = [0_u8; 8];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok()
        && b == MAGIC
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    fn key(b: u8) -> BackupKey {
        BackupKey::from_slice(&[b; 32]).unwrap()
    }

    fn seal(k: &BackupKey, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt_with_salt(k, &[7; SALT_LEN], &mut &data[..], &mut out).unwrap();
        out
    }

    fn open(k: &BackupKey, ct: &[u8]) -> Result<Vec<u8>, BackupCryptoError> {
        let mut out = Vec::new();
        decrypt_stream(k, &mut &ct[..], &mut out)?;
        Ok(out)
    }

    #[test]
    fn round_trips_across_chunk_boundaries() {
        let k = key(1);
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 5] {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let ct = seal(&k, &data);
            assert_eq!(open(&k, &ct).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn key_never_shows_in_debug_or_errors() {
        let k = key(0x41);
        assert_eq!(format!("{k:?}"), "BackupKey([REDACTED])");
        let e = open(&key(2), &seal(&k, b"x")).unwrap_err().to_string();
        assert!(!e.contains("AAAA"), "{e}");
    }

    #[test]
    fn wrong_key_and_foreign_files_are_told_apart_from_tampering() {
        let ct = seal(&key(1), b"secret database");
        assert!(matches!(
            open(&key(2), &ct),
            Err(BackupCryptoError::WrongKey)
        ));
        assert!(matches!(
            open(&key(1), b"SQLite format 3\0........"),
            Err(BackupCryptoError::NotEncrypted)
        ));
        let mut v = ct.clone();
        v[8] = 9;
        assert!(matches!(
            open(&key(1), &v),
            Err(BackupCryptoError::Unsupported(9))
        ));
    }

    #[test]
    fn every_single_byte_flip_is_detected() {
        let k = key(3);
        let ct = seal(&k, b"0123456789abcdef");
        for i in 0..ct.len() {
            let mut v = ct.clone();
            v[i] ^= 0x01;
            assert!(open(&k, &v).is_err(), "flip at byte {i} went unnoticed");
        }
    }

    #[test]
    fn truncation_reordering_and_extension_are_detected() {
        let k = key(4);
        let data = vec![9_u8; 2 * CHUNK + 10];
        let ct = seal(&k, &data);
        let ct_chunk = CHUNK + TAG;
        // Cut at a chunk boundary (drops the final chunk), inside a tag, and at the header.
        for cut in [
            HEADER_LEN + ct_chunk,
            HEADER_LEN + 2 * ct_chunk,
            ct.len() - 1,
            HEADER_LEN,
        ] {
            assert!(matches!(
                open(&k, &ct[..cut]),
                Err(BackupCryptoError::Tampered)
            ));
        }
        // Swapped first two chunks.
        let mut v = ct.clone();
        let (a, b) = (HEADER_LEN, HEADER_LEN + ct_chunk);
        let first: Vec<u8> = v[a..b].to_vec();
        let second: Vec<u8> = v[b..b + ct_chunk].to_vec();
        v[a..b].copy_from_slice(&second);
        v[b..b + ct_chunk].copy_from_slice(&first);
        assert!(open(&k, &v).is_err());
        // Appended junk and appended copy of a valid chunk.
        let mut v = ct.clone();
        v.push(0);
        assert!(open(&k, &v).is_err());
        let mut v = ct.clone();
        v.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + ct_chunk]);
        assert!(open(&k, &v).is_err());
    }

    #[test]
    fn two_encryptions_of_the_same_data_differ() {
        let k = key(5);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        encrypt_stream(&k, &mut &b"same"[..], &mut a).unwrap();
        encrypt_stream(&k, &mut &b"same"[..], &mut b).unwrap();
        assert_ne!(a, b);
        assert_eq!(open(&k, &a).unwrap(), open(&k, &b).unwrap());
    }

    #[test]
    fn decrypt_file_publishes_only_after_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(6);
        let src = dir.path().join("a.enc");
        let mut ct = seal(&k, b"hello");
        fs::write(&src, &ct).unwrap();
        let out = dir.path().join("a.sqlite");
        decrypt_file(&k, &src, &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"hello");
        // Never overwrites.
        assert!(decrypt_file(&k, &src, &out).is_err());
        // Tampered: nothing published, no temp file left.
        let last = ct.len() - 1;
        ct[last] ^= 1;
        fs::write(&src, &ct).unwrap();
        let out2 = dir.path().join("b.sqlite");
        assert!(matches!(
            decrypt_file(&k, &src, &out2),
            Err(BackupCryptoError::Tampered)
        ));
        assert!(!out2.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
