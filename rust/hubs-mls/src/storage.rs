//! Group state for one device, held in memory and handed to the app as one
//! snapshot per conversation (the website keeps one `conversation:<id>`
//! value per conversation the same way). The app keeps snapshots in its
//! encrypted database; the core never touches disk.
//!
//! A snapshot holds secrets: the group's epoch secrets, this device's
//! signing key and the last few epochs kept for late messages.
//!
//! Format, all integers big-endian:
//! `"HMLS"`, version `1`, group id (u32 length + bytes), state (u32 length +
//! bytes), epoch count (u32), then each epoch: id (u64), u32 length + bytes.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
};

use mls_rs::GroupStateStorage;
use mls_rs_core::group::{EpochRecord, GroupState};
use zeroize::Zeroizing;

use crate::error::{malformed, Result};

/// Past epochs kept for late messages: 4, the ts-mls default
/// (`defaultKeyRetentionConfig`), which the website uses.
pub const EPOCH_RETENTION: usize = 4;

const MAGIC: &[u8; 4] = b"HMLS";
const VERSION: u8 = 1;

#[derive(Clone, Default)]
struct GroupData {
    state: Zeroizing<Vec<u8>>,
    epochs: VecDeque<EpochRecord>,
}

#[derive(Clone, Default)]
pub struct SnapshotStore {
    groups: Arc<Mutex<HashMap<Vec<u8>, GroupData>>>,
}

impl SnapshotStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, GroupData>> {
        self.groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// One conversation's snapshot, or `None` before it was first saved.
    pub fn export(&self, group_id: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let groups = self.lock();
        let data = groups.get(group_id)?;
        let mut out = Zeroizing::new(Vec::with_capacity(data.state.len() + 64));
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        put_bytes(&mut out, group_id);
        put_bytes(&mut out, &data.state);
        out.extend_from_slice(&(data.epochs.len() as u32).to_be_bytes());
        for epoch in &data.epochs {
            out.extend_from_slice(&epoch.id.to_be_bytes());
            put_bytes(&mut out, &epoch.data);
        }
        Some(out)
    }

    /// Load a snapshot, replacing what this store held for its group.
    /// Returns the group id.
    pub fn import(&self, snapshot: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Reader(snapshot);
        if reader.take(4)? != MAGIC || reader.take(1)? != [VERSION] {
            return Err(malformed("not a Hubs MLS snapshot"));
        }
        let group_id = reader.bytes()?.to_vec();
        let state = Zeroizing::new(reader.bytes()?.to_vec());
        let count = reader.u32()? as usize;
        if count > EPOCH_RETENTION + 1 {
            return Err(malformed("too many epochs in the snapshot"));
        }
        let mut epochs = VecDeque::with_capacity(count);
        for _ in 0..count {
            let id = reader.u64()?;
            epochs.push_back(EpochRecord::new(
                id,
                Zeroizing::new(reader.bytes()?.to_vec()),
            ));
        }
        if !reader.0.is_empty() {
            return Err(malformed("bytes after the snapshot"));
        }
        self.lock()
            .insert(group_id.clone(), GroupData { state, epochs });
        Ok(group_id)
    }

    pub fn remove(&self, group_id: &[u8]) {
        self.lock().remove(group_id);
    }

    /// Drops the past epochs unless the newest is the one before `current`.
    pub fn drop_stale_epochs(&self, group_id: &[u8], current: u64) {
        if let Some(data) = self.lock().get_mut(group_id) {
            if data
                .epochs
                .back()
                .is_some_and(|epoch| epoch.id + 1 != current)
            {
                data.epochs.clear();
            }
        }
    }
}

/// A snapshot in this store's format for one group's state with no past
/// epochs (the interop import, `interop.rs`).
pub(crate) fn wrap_snapshot(group_id: &[u8], state: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(state.len() + group_id.len() + 17);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    put_bytes(&mut out, group_id);
    put_bytes(&mut out, state);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.0.len() < count {
            return Err(malformed("the snapshot is cut short"));
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        self.take(length)
    }
}

impl GroupStateStorage for SnapshotStore {
    type Error = Infallible;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.lock().get(group_id).map(|data| data.state.clone()))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.lock().get(group_id).and_then(|data| {
            data.epochs
                .iter()
                .find(|epoch| epoch.id == epoch_id)
                .map(|epoch| epoch.data.clone())
        }))
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let mut groups = self.lock();
        let data = groups.entry(state.id).or_default();
        data.state = state.data;
        for update in epoch_updates {
            if let Some(existing) = data.epochs.iter_mut().find(|epoch| epoch.id == update.id) {
                *existing = update;
            }
        }
        data.epochs.extend(epoch_inserts);
        while data.epochs.len() > EPOCH_RETENTION {
            data.epochs.pop_front();
        }
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self
            .lock()
            .get(group_id)
            .and_then(|data| data.epochs.back().map(|epoch| epoch.id)))
    }
}
