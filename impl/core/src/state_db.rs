//! RocksDB-backed consensus state store.
//!
//! Phase 1: open + schema version, load/restore `Node`, migrate legacy
//! `zcrypt-state.bin` postcard dumps, incremental commitment/nullifier puts.
//! Phase 2: `WriteBatch` + fsync, fail-closed commit errors, commit stats,
//! optional postcard backup export (same bytes as the old single-file format).
//!
//! Working state remains in RAM (`Node`). The DB is the durable log of that
//! state so a restart reloads without replaying the whole chain from genesis.

use std::path::{Path, PathBuf};
use std::time::Instant;

use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use zcrypt_shield::Commitment;

use crate::node::{ImmatureMint, Node, NodeSnapshot, Sentinel};

/// On-disk schema for this module. Bump when key layout changes; older DBs
/// refuse to open (re-migrate from postcard backup or relaunch) rather than
/// silently misparse.
pub const STATE_DB_SCHEMA: u32 = 1;

// ---- key layout (default column family) ------------------------------------
// meta/schema        -> u32 LE
// meta/height        -> u64 LE
// meta/commit_count  -> u64 LE  (number of commitment leaves flushed)
// meta/nf_count      -> u64 LE  (number of nullifier keys flushed)
// c/{u64 BE}         -> commitment leaf (8 × u64 LE = 64 bytes)
// nf/{32 bytes}      -> txbind (32 bytes)
// blob/staking       -> postcard
// blob/assets        -> postcard
// blob/htlc          -> postcard
// blob/spv           -> postcard
// blob/immature      -> postcard
// blob/recent_roots  -> postcard
// blob/sentinel      -> postcard of Option<Sentinel>

const K_SCHEMA: &[u8] = b"meta/schema";
const K_HEIGHT: &[u8] = b"meta/height";
const K_COMMIT_COUNT: &[u8] = b"meta/commit_count";
const K_NF_COUNT: &[u8] = b"meta/nf_count";
const P_COMMIT: &[u8] = b"c/";
const P_NF: &[u8] = b"nf/";
const K_STAKING: &[u8] = b"blob/staking";
const K_ASSETS: &[u8] = b"blob/assets";
const K_HTLC: &[u8] = b"blob/htlc";
const K_SPV: &[u8] = b"blob/spv";
const K_IMMATURE: &[u8] = b"blob/immature";
const K_RECENT_ROOTS: &[u8] = b"blob/recent_roots";
const K_SENTINEL: &[u8] = b"blob/sentinel";

/// Stats from one successful `commit` (phase-2 observability).
#[derive(Clone, Debug, Default)]
pub struct CommitStats {
    pub height: u64,
    pub new_commitments: usize,
    pub new_nullifiers: usize,
    pub total_commitments: usize,
    pub total_nullifiers: usize,
    pub batch_puts: usize,
    /// Wall time for building + writing the batch (including fsync).
    pub elapsed_ms: u128,
}

/// Incremental RocksDB store for a single node's consensus state.
pub struct StateDb {
    db: DB,
    path: PathBuf,
    /// Append cursor: how many commitment leaves are already on disk.
    commit_count: usize,
    /// How many nullifier keys we believe are on disk (for stats; puts are idempotent).
    nf_count: usize,
}

impl StateDb {
    /// Open (or create) a RocksDB at `path`. Does not load a `Node` — call [`Self::load`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create state db parent {}: {e}", parent.display()))?;
        }
        let mut opts = Options::default();
        opts.create_if_missing(true);
        // Keep a modest write buffer; consensus commits are infrequent vs trading DBs.
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = DB::open(&opts, &path).map_err(|e| format!("open rocksdb {}: {e}", path.display()))?;

        let mut store = StateDb {
            db,
            path,
            commit_count: 0,
            nf_count: 0,
        };
        store.init_or_check_schema()?;
        store.refresh_cursors_from_meta()?;
        Ok(store)
    }

    /// Open the DB, optionally importing a legacy postcard `zcrypt-state.bin` when the
    /// DB is empty. Returns `(store, loaded_node_and_height)`.
    ///
    /// * If the DB already has state → load from DB (legacy file ignored).
    /// * If the DB is empty and `legacy_bin` exists → import full snapshot, then load.
    /// * If both empty → `(store, None)` fresh chain.
    pub fn open_or_migrate(
        db_path: impl AsRef<Path>,
        legacy_bin: Option<&Path>,
    ) -> Result<(Self, Option<(Node, u64)>), String> {
        let mut store = Self::open(db_path)?;
        if store.has_state()? {
            let loaded = store
                .load()?
                .ok_or_else(|| "meta present but load returned None".to_string())?;
            eprintln!(
                "[state-db] resumed from {} at height {}",
                store.path.display(),
                loaded.1
            );
            return Ok((store, Some(loaded)));
        }
        if let Some(bin) = legacy_bin {
            if bin.is_file() {
                eprintln!(
                    "[state-db] migrating legacy snapshot {} → {}",
                    bin.display(),
                    store.path.display()
                );
                store.migrate_from_bin(bin)?;
                let loaded = store
                    .load()?
                    .ok_or_else(|| "migration wrote meta but load failed".to_string())?;
                eprintln!(
                    "[state-db] migration complete at height {}",
                    loaded.1
                );
                return Ok((store, Some(loaded)));
            }
        }
        eprintln!(
            "[state-db] fresh store at {} (no prior state)",
            store.path.display()
        );
        Ok((store, None))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn init_or_check_schema(&mut self) -> Result<(), String> {
        match self.db.get(K_SCHEMA).map_err(|e| e.to_string())? {
            None => {
                // Empty or brand-new DB: stamp schema when we first commit.
                // Leave absent so `has_state` is false until first commit/migrate.
                Ok(())
            }
            Some(bytes) => {
                if bytes.len() < 4 {
                    return Err("corrupt meta/schema".into());
                }
                let v = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                if v != STATE_DB_SCHEMA {
                    return Err(format!(
                        "state db schema {v} != expected {STATE_DB_SCHEMA} \
                         (no automatic migration; restore from postcard backup or relaunch)"
                    ));
                }
                Ok(())
            }
        }
    }

    fn refresh_cursors_from_meta(&mut self) -> Result<(), String> {
        self.commit_count = self.get_u64(K_COMMIT_COUNT)?.unwrap_or(0) as usize;
        self.nf_count = self.get_u64(K_NF_COUNT)?.unwrap_or(0) as usize;
        Ok(())
    }

    fn has_state(&self) -> Result<bool, String> {
        Ok(self.db.get(K_HEIGHT).map_err(|e| e.to_string())?.is_some())
    }

    fn get_u64(&self, key: &[u8]) -> Result<Option<u64>, String> {
        match self.db.get(key).map_err(|e| e.to_string())? {
            None => Ok(None),
            Some(b) if b.len() >= 8 => {
                Ok(Some(u64::from_le_bytes(b[..8].try_into().unwrap())))
            }
            Some(_) => Err(format!("corrupt u64 at key {}", String::from_utf8_lossy(key))),
        }
    }

    /// Load consensus state from the DB. `None` if the store has never been committed.
    pub fn load(&self) -> Result<Option<(Node, u64)>, String> {
        let height = match self.get_u64(K_HEIGHT)? {
            Some(h) => h,
            None => return Ok(None),
        };
        if let Some(schema_bytes) = self.db.get(K_SCHEMA).map_err(|e| e.to_string())? {
            let v = u32::from_le_bytes(
                schema_bytes
                    .get(..4)
                    .ok_or("short schema")?
                    .try_into()
                    .unwrap(),
            );
            if v != STATE_DB_SCHEMA {
                return Err(format!(
                    "state db schema {v} != expected {STATE_DB_SCHEMA}"
                ));
            }
        }

        let commit_count = self.get_u64(K_COMMIT_COUNT)?.unwrap_or(0) as usize;
        let mut commitment_leaves = Vec::with_capacity(commit_count);
        for i in 0..commit_count {
            let key = commit_key(i as u64);
            let bytes = self
                .db
                .get(&key)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("missing commitment leaf {i}"))?;
            commitment_leaves.push(decode_commitment(&bytes)?);
        }

        let mut smt_leaves = Vec::new();
        let mut iter = self.db.prefix_iterator(P_NF);
        while let Some(item) = iter.next() {
            let (k, v) = item.map_err(|e| e.to_string())?;
            if !k.starts_with(P_NF) {
                break;
            }
            if k.len() != P_NF.len() + 32 {
                return Err(format!("corrupt nf key length {}", k.len()));
            }
            if v.len() != 32 {
                return Err(format!("corrupt nf value length {}", v.len()));
            }
            let mut nf = [0u8; 32];
            nf.copy_from_slice(&k[P_NF.len()..]);
            let mut bind = [0u8; 32];
            bind.copy_from_slice(&v);
            smt_leaves.push((nf, bind));
        }

        let staking = load_blob(&self.db, K_STAKING)?;
        let assets = load_blob(&self.db, K_ASSETS)?;
        let htlc = load_blob(&self.db, K_HTLC)?;
        let spv = load_blob(&self.db, K_SPV)?;
        let immature: Vec<ImmatureMint> = load_blob(&self.db, K_IMMATURE)?;
        let recent_roots: Vec<Commitment> = load_blob(&self.db, K_RECENT_ROOTS)?;
        let sentinel: Option<Sentinel> = match self.db.get(K_SENTINEL).map_err(|e| e.to_string())? {
            None => None,
            Some(b) if b.is_empty() => None,
            Some(b) => {
                postcard::from_bytes(&b).map_err(|e| format!("decode sentinel: {e}"))?
            }
        };

        let snap = NodeSnapshot {
            version: crate::node::SNAPSHOT_VERSION_PUB,
            height,
            commitment_leaves,
            smt_leaves,
            staking,
            assets,
            htlc,
            recent_roots,
            spv,
            immature,
            sentinel,
        };
        let (node, h) = Node::restore(snap);
        Ok(Some((node, h)))
    }

    /// Persist `node` at `height` with a synced WriteBatch.
    ///
    /// * New commitment leaves are appended (cursor-based).
    /// * Nullifiers are put by key (idempotent; only truly new keys add work).
    /// * Subsystem blobs (staking, assets, HTLC, SPV, …) are rewritten each commit
    ///   (small relative to the leaf sets as the chain grows).
    pub fn commit(&mut self, node: &Node, height: u64) -> Result<CommitStats, String> {
        let t0 = Instant::now();
        let snap = node.snapshot(height);
        let total_c = snap.commitment_leaves.len();
        let total_nf = snap.smt_leaves.len();

        if total_c < self.commit_count {
            return Err(format!(
                "commitment tree shrank (disk {}, memory {total_c}) — refusing commit",
                self.commit_count
            ));
        }

        let mut batch = WriteBatch::default();
        let mut puts = 0usize;

        batch.put(K_SCHEMA, STATE_DB_SCHEMA.to_le_bytes());
        batch.put(K_HEIGHT, height.to_le_bytes());
        puts += 2;

        let new_commitments = total_c - self.commit_count;
        for i in self.commit_count..total_c {
            let key = commit_key(i as u64);
            let val = encode_commitment(&snap.commitment_leaves[i]);
            batch.put(&key, &val);
            puts += 1;
        }
        batch.put(K_COMMIT_COUNT, (total_c as u64).to_le_bytes());
        puts += 1;

        // Idempotent puts; count "new" as growth in cardinality for stats.
        let prev_nf = self.nf_count;
        for (nf, bind) in &snap.smt_leaves {
            let mut key = Vec::with_capacity(P_NF.len() + 32);
            key.extend_from_slice(P_NF);
            key.extend_from_slice(nf);
            batch.put(&key, bind);
            puts += 1;
        }
        batch.put(K_NF_COUNT, (total_nf as u64).to_le_bytes());
        puts += 1;

        put_blob(&mut batch, K_STAKING, &snap.staking)?;
        put_blob(&mut batch, K_ASSETS, &snap.assets)?;
        put_blob(&mut batch, K_HTLC, &snap.htlc)?;
        put_blob(&mut batch, K_SPV, &snap.spv)?;
        put_blob(&mut batch, K_IMMATURE, &snap.immature)?;
        put_blob(&mut batch, K_RECENT_ROOTS, &snap.recent_roots)?;
        puts += 6;
        let sent_bytes = postcard::to_allocvec(&snap.sentinel)
            .map_err(|e| format!("encode sentinel: {e}"))?;
        batch.put(K_SENTINEL, sent_bytes);
        puts += 1;

        let mut wopts = WriteOptions::default();
        wopts.set_sync(true); // phase 2: fsync WAL+SST visibility before Commit returns
        self.db
            .write_opt(batch, &wopts)
            .map_err(|e| format!("rocksdb write (height {height}): {e}"))?;

        self.commit_count = total_c;
        self.nf_count = total_nf;

        let new_nullifiers = total_nf.saturating_sub(prev_nf);
        let stats = CommitStats {
            height,
            new_commitments,
            new_nullifiers,
            total_commitments: total_c,
            total_nullifiers: total_nf,
            batch_puts: puts,
            elapsed_ms: t0.elapsed().as_millis(),
        };
        Ok(stats)
    }

    /// Import a legacy single-file postcard snapshot into this (empty) DB.
    pub fn migrate_from_bin(&mut self, path: &Path) -> Result<(), String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("read legacy {}: {e}", path.display()))?;
        let (node, height) = Node::from_snapshot_bytes(&bytes)?;
        // Reset cursors so commit writes every leaf.
        self.commit_count = 0;
        self.nf_count = 0;
        let _ = self.commit(&node, height)?;
        Ok(())
    }

    /// Postcard export of the live node (same format as the old `zcrypt-state.bin`).
    pub fn export_snapshot_bytes(node: &Node, height: u64) -> Vec<u8> {
        node.to_snapshot_bytes(height)
    }

    /// Write a postcard backup next to the DB (or to `path`). Atomic temp+rename.
    pub fn write_backup_file(path: &Path, node: &Node, height: u64) -> Result<(), String> {
        let bytes = Self::export_snapshot_bytes(node, height);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("backup mkdir {}: {e}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| format!("backup write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("backup rename → {}: {e}", path.display()))?;
        Ok(())
    }
}

fn commit_key(index: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(P_COMMIT.len() + 8);
    k.extend_from_slice(P_COMMIT);
    k.extend_from_slice(&index.to_be_bytes()); // BE so prefix iteration is ordered
    k
}

fn encode_commitment(c: &Commitment) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, limb) in c.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn decode_commitment(bytes: &[u8]) -> Result<Commitment, String> {
    if bytes.len() != 64 {
        return Err(format!("commitment leaf must be 64 bytes, got {}", bytes.len()));
    }
    let mut c = [0u64; 8];
    for i in 0..8 {
        c[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    Ok(c)
}

fn put_blob<T: serde::Serialize>(batch: &mut WriteBatch, key: &[u8], val: &T) -> Result<(), String> {
    let bytes = postcard::to_allocvec(val).map_err(|e| format!("encode blob: {e}"))?;
    batch.put(key, bytes);
    Ok(())
}

fn load_blob<T: serde::de::DeserializeOwned>(db: &DB, key: &[u8]) -> Result<T, String> {
    let bytes = db
        .get(key)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("missing blob {}", String::from_utf8_lossy(key)))?;
    postcard::from_bytes(&bytes).map_err(|e| format!("decode {}: {e}", String::from_utf8_lossy(key)))
}

// Re-export for state_db: Node keeps SNAPSHOT_VERSION private; expose a pub const.
// (Defined below after we add SNAPSHOT_VERSION_PUB on node.)

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_db() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "zcrypt-state-db-{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample_node(height: u64, coins: u64) -> Node {
        let mut node = Node::new();
        node.mint_foundation([0xF0; 32]);
        node.set_height(height);
        for k in 0..coins {
            node.seed_coin([k + 100; 8]);
        }
        node
    }

    #[test]
    fn commit_load_preserves_app_hash_and_height() {
        let dir = tmp_db();
        let mut db = StateDb::open(&dir).expect("open");
        let node = sample_node(7, 5);
        let hash = node.state_root();
        let stats = db.commit(&node, 7).expect("commit");
        assert_eq!(stats.new_commitments, 5);
        assert_eq!(stats.total_commitments, 5);
        assert!(stats.elapsed_ms < 60_000);

        drop(db);
        let db2 = StateDb::open(&dir).expect("reopen");
        let (loaded, h) = db2.load().expect("load ok").expect("some state");
        assert_eq!(h, 7);
        assert_eq!(loaded.state_root(), hash);
        assert_eq!(loaded.commitment_count(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incremental_commit_only_appends_new_leaves() {
        let dir = tmp_db();
        let mut db = StateDb::open(&dir).expect("open");
        let mut node = sample_node(1, 3);
        let s1 = db.commit(&node, 1).expect("c1");
        assert_eq!(s1.new_commitments, 3);

        node.set_height(2);
        node.seed_coin([9u64; 8]);
        node.seed_coin([10u64; 8]);
        let s2 = db.commit(&node, 2).expect("c2");
        assert_eq!(s2.new_commitments, 2, "only the two new leaves");
        assert_eq!(s2.total_commitments, 5);

        let hash = node.state_root();
        drop(db);
        let (loaded, h) = StateDb::open(&dir)
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(h, 2);
        assert_eq!(loaded.state_root(), hash);
        assert_eq!(loaded.commitment_count(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migrate_from_legacy_bin() {
        let dir = tmp_db();
        let bin = dir.with_extension("legacy.bin");
        let node = sample_node(42, 8);
        let hash = node.state_root();
        std::fs::write(&bin, node.to_snapshot_bytes(42)).unwrap();

        let (db, loaded) = StateDb::open_or_migrate(&dir, Some(&bin)).expect("migrate");
        let (loaded, h) = loaded.expect("migrated node");
        assert_eq!(h, 42);
        assert_eq!(loaded.state_root(), hash);
        // Second open uses DB only (legacy ignored once meta exists).
        drop(db);
        let (_db2, loaded2) = StateDb::open_or_migrate(&dir, Some(&bin)).unwrap();
        let (n2, h2) = loaded2.unwrap();
        assert_eq!(h2, 42);
        assert_eq!(n2.state_root(), hash);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&bin);
    }

    #[test]
    fn postcard_backup_roundtrip() {
        let dir = tmp_db();
        let mut db = StateDb::open(&dir).unwrap();
        let node = sample_node(3, 2);
        db.commit(&node, 3).unwrap();
        let backup = dir.join("backup.bin");
        StateDb::write_backup_file(&backup, &node, 3).unwrap();
        let (restored, h) = Node::from_snapshot_bytes(&std::fs::read(&backup).unwrap()).unwrap();
        assert_eq!(h, 3);
        assert_eq!(restored.state_root(), node.state_root());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_db_load_is_none() {
        let dir = tmp_db();
        let db = StateDb::open(&dir).unwrap();
        assert!(db.load().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -------------------------------------------------------------------------
    // Crash / recovery suite
    //
    // Models the ABCI lifecycle without a real kill-9 mid-write (RocksDB
    // WriteBatch is all-or-nothing; we can't half-apply a batch). We do verify:
    //   * durable height is only the last successful Commit
    //   * crash after Finalize-in-RAM but before Commit loses the block (replay)
    //   * failed Commit does not advance disk height or leaf cursors
    //   * multi-commit chains reopen at the last durable height only
    //   * backup lag does not corrupt the DB view of truth
    // -------------------------------------------------------------------------

    /// Crash after `finalize_block` (RAM advanced) but before `Commit` (no persist).
    /// On restart the durable height must be the prior Commit — CometBFT replays.
    #[test]
    fn crash_before_commit_keeps_prior_durable_height() {
        let dir = tmp_db();
        let mut db = StateDb::open(&dir).unwrap();

        let mut node = sample_node(1, 2);
        let hash_h1 = node.state_root();
        db.commit(&node, 1).expect("commit h1");

        // Simulate finalize_block for height 2 in RAM only — never Commit.
        node.set_height(2);
        node.seed_coin([42u64; 8]);
        let hash_h2_ram = node.state_root();
        assert_ne!(hash_h1, hash_h2_ram, "RAM moved to a new app_hash");

        // Process crash: drop store without committing height 2.
        drop(db);
        drop(node);

        let (loaded, h) = StateDb::open(&dir)
            .unwrap()
            .load()
            .unwrap()
            .expect("h1 durable");
        assert_eq!(h, 1, "only last Commit is durable");
        assert_eq!(loaded.state_root(), hash_h1);
        assert_eq!(loaded.commitment_count(), 2, "height-2 leaf never flushed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// N successful Commits, then hard reopen (no graceful flush beyond sync write).
    /// Durable state must match the last Commit only.
    #[test]
    fn multi_commit_crash_reopen_at_last_height_only() {
        let dir = tmp_db();
        let mut hashes = Vec::new();
        {
            let mut db = StateDb::open(&dir).unwrap();
            let mut node = sample_node(0, 0);
            for h in 1..=5u64 {
                node.set_height(h);
                node.seed_coin([h + 50; 8]);
                db.commit(&node, h).unwrap();
                hashes.push((h, node.state_root(), node.commitment_count()));
            }
            // Abrupt drop = process exit after last synced commit.
        }

        let (loaded, h) = StateDb::open(&dir).unwrap().load().unwrap().unwrap();
        let (last_h, last_hash, last_c) = hashes.last().copied().unwrap();
        assert_eq!(h, last_h);
        assert_eq!(loaded.state_root(), last_hash);
        assert_eq!(loaded.commitment_count(), last_c);

        // Intermediate heights are not loadable as separate checkpoints; we only
        // keep the tip. Verify tip is height 5 with 5 coins.
        assert_eq!(h, 5);
        assert_eq!(loaded.commitment_count(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A Commit that returns Err must not move durable height / leaf counts.
    /// (Models disk-full / write failure after a good height is already on disk.)
    #[test]
    fn failed_commit_does_not_advance_disk() {
        let dir = tmp_db();
        let mut db = StateDb::open(&dir).unwrap();

        let good = sample_node(3, 4);
        let good_hash = good.state_root();
        db.commit(&good, 3).unwrap();
        assert_eq!(db.commit_count, 4);

        // Shrinkage is refused: would indicate a forked/broken Node. Disk stays at h=3.
        let mut bad = Node::new();
        bad.set_height(4);
        // zero coins → total_c (0) < commit_count (4)
        let err = db.commit(&bad, 4).expect_err("must refuse shrink");
        assert!(
            err.contains("shrank"),
            "unexpected error: {err}"
        );
        assert_eq!(db.commit_count, 4, "in-memory cursor unchanged on Err");

        drop(db);
        let (loaded, h) = StateDb::open(&dir).unwrap().load().unwrap().unwrap();
        assert_eq!(h, 3, "disk height unchanged after failed commit");
        assert_eq!(loaded.state_root(), good_hash);
        assert_eq!(loaded.commitment_count(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After a failed commit attempt, a subsequent valid commit still works and
    /// only appends the true delta from the last durable cursor.
    #[test]
    fn recover_after_failed_commit_then_succeed() {
        let dir = tmp_db();
        let mut db = StateDb::open(&dir).unwrap();
        let mut node = sample_node(1, 2);
        db.commit(&node, 1).unwrap();

        let mut bad = Node::new();
        bad.set_height(2);
        assert!(db.commit(&bad, 2).is_err());

        // Real block 2: extend the same chain that was durable at h=1.
        node.set_height(2);
        node.seed_coin([7u64; 8]);
        let stats = db.commit(&node, 2).expect("commit after failed attempt");
        assert_eq!(stats.new_commitments, 1);
        assert_eq!(stats.total_commitments, 3);
        let hash = node.state_root();

        drop(db);
        let (loaded, h) = StateDb::open(&dir).unwrap().load().unwrap().unwrap();
        assert_eq!(h, 2);
        assert_eq!(loaded.state_root(), hash);
        assert_eq!(loaded.commitment_count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Postcard backup is not atomic with the DB. If backup is stale/missing,
    /// RocksDB remains source of truth on reopen.
    #[test]
    fn stale_or_missing_backup_does_not_affect_db_truth() {
        let dir = tmp_db();
        let backup = dir.join("backup.bin");
        let mut db = StateDb::open(&dir).unwrap();

        let n1 = sample_node(1, 1);
        let h1 = n1.state_root();
        db.commit(&n1, 1).unwrap();
        StateDb::write_backup_file(&backup, &n1, 1).unwrap();

        let mut n2 = n1;
        n2.set_height(2);
        n2.seed_coin([9u64; 8]);
        let h2 = n2.state_root();
        db.commit(&n2, 2).unwrap();
        // Crash before backup update: leave backup at height 1.
        assert!(backup.is_file());
        let (bak_node, bak_h) =
            Node::from_snapshot_bytes(&std::fs::read(&backup).unwrap()).unwrap();
        assert_eq!(bak_h, 1);
        assert_eq!(bak_node.state_root(), h1);

        drop(db);
        // Reopen uses DB, not backup.
        let (loaded, h) = StateDb::open(&dir).unwrap().load().unwrap().unwrap();
        assert_eq!(h, 2, "DB tip wins over stale backup");
        assert_eq!(loaded.state_root(), h2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unix: make the DB directory non-writable so the next WriteBatch fails.
    /// Durable state must remain at the last successful height.
    #[cfg(unix)]
    #[test]
    fn disk_write_failure_preserves_last_good_commit() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tmp_db();
        let mut db = StateDb::open(&dir).unwrap();
        let good = sample_node(2, 3);
        let good_hash = good.state_root();
        db.commit(&good, 2).unwrap();
        drop(db);

        // Freeze the directory: new SST/WAL files cannot be created.
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&dir, perms).unwrap();

        let write_failed = (|| -> Result<(), String> {
            let mut db = StateDb::open(&dir).map_err(|e| e)?;
            let mut next = good;
            next.set_height(3);
            next.seed_coin([99u64; 8]);
            db.commit(&next, 3).map(|_| ()).map_err(|e| e)
        })();

        // Restore perms before asserts/cleanup so we can always delete the dir.
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dir, perms).unwrap();

        assert!(
            write_failed.is_err(),
            "expected rocksdb write to fail on read-only dir, got Ok"
        );

        let (loaded, h) = StateDb::open(&dir).unwrap().load().unwrap().unwrap();
        assert_eq!(h, 2, "failed write must not advance height");
        assert_eq!(loaded.state_root(), good_hash);
        assert_eq!(loaded.commitment_count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reopen reloads cursors from meta so a second process continues appending
    /// (not rewriting from zero) after a crash.
    #[test]
    fn reopen_restores_append_cursor() {
        let dir = tmp_db();
        {
            let mut db = StateDb::open(&dir).unwrap();
            let node = sample_node(1, 10);
            db.commit(&node, 1).unwrap();
            assert_eq!(db.commit_count, 10);
        }
        let mut db = StateDb::open(&dir).unwrap();
        assert_eq!(db.commit_count, 10, "cursor reloaded from meta/commit_count");
        let mut node = sample_node(1, 10);
        // Rebuild equivalent tree then add one leaf (same foundation + 10 seeds).
        node.set_height(2);
        node.seed_coin([200u64; 8]);
        let stats = db.commit(&node, 2).unwrap();
        assert_eq!(stats.new_commitments, 1, "only the new leaf is written");
        assert_eq!(stats.total_commitments, 11);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
