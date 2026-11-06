//! Missing messages, the web's `trackGeneration` and `dueGenerations`.
//!
//! Every MLS application message carries, in its encrypted sender data,
//! the sender's leaf and its generation: its place in that leaf's
//! application ratchet for the epoch, counting from 0 (RFC 9420, sections
//! 6.3.2 and 9.1). `MlsGroup::message_header` reads them. Messages from one
//! device reach the server in order, so a generation skipped for longer
//! than `MISSING_MESSAGE_GRACE_MS` is a message that did not arrive, not
//! one reordered on the way.
//!
//! The app keeps one `GenerationTrack` per epoch and sender leaf, for the
//! other person's leaves only, and only for epochs at or after the first
//! one it followed from its start: the epoch it joined with a welcome, 0
//! for a group it created, otherwise the epoch of the first commit it
//! accepts or makes. For each arrival (whether the message then opens or
//! not) it calls `track_generation`; after each sync, `due_generations`
//! for every track, and each track with due gaps becomes one notice placed
//! just before the earliest `before`. A track goes once its epoch is more
//! than `EPOCH_RETENTION` behind the newest epoch seen and it has no open
//! gaps. These functions are pure; the app stores the tracks.

/// How long a gap may stay open before it is told (2 minutes).
pub const MISSING_MESSAGE_GRACE_MS: u64 = 120_000;
/// The most generations one arrival can open as gaps: MLS opens a message
/// at most this far ahead of the next one expected.
pub const MAX_GENERATION_GAP: u32 = 200;

/// A generation not seen yet.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GenerationGap {
    pub generation: u32,
    /// When the gap was noticed (milliseconds since 1970).
    pub at: i64,
    /// Where its notice goes: one millisecond before the shown time of the
    /// message that revealed the gap.
    pub before: i64,
}

/// A generation already told as missing, and the notice that told it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ToldGeneration {
    pub generation: u32,
    pub notice: String,
}

/// One sender leaf's messages in one epoch, as this device saw them.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GenerationTrack {
    /// The sender's account, for the notice.
    pub user_id: String,
    /// The next generation expected; a new track starts at 0.
    pub next: u32,
    /// Gaps not yet told, oldest first.
    pub gaps: Vec<GenerationGap>,
    /// Gaps already told.
    pub told: Vec<ToldGeneration>,
}

/// The track after an arrival, and the notice it settles, if any: count
/// that notice down by one, and delete it at 0.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TrackedArrival {
    pub track: GenerationTrack,
    pub settled: Option<String>,
}

/// The track after a check, and the gaps that became one notice.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DueGenerations {
    pub track: GenerationTrack,
    pub due: Vec<GenerationGap>,
}

#[uniffi::export]
pub fn missing_message_grace_ms() -> u64 {
    MISSING_MESSAGE_GRACE_MS
}

/// Note that the message with `generation` arrived at `now_ms`, shown at
/// `shown_at_ms`. A jump ahead opens a gap for each generation skipped (at
/// most `MAX_GENERATION_GAP`); an earlier generation closes its gap,
/// quietly when it was not told yet, or settles the notice that told it.
/// A repeat changes nothing.
#[uniffi::export]
pub fn track_generation(
    track: GenerationTrack,
    generation: u32,
    now_ms: i64,
    shown_at_ms: i64,
) -> TrackedArrival {
    let mut track = track;
    if generation >= track.next {
        let first = track
            .next
            .max(generation.saturating_sub(MAX_GENERATION_GAP));
        let before = shown_at_ms.saturating_sub(1);
        track
            .gaps
            .extend((first..generation).map(|skipped| GenerationGap {
                generation: skipped,
                at: now_ms,
                before,
            }));
        track.next = generation.saturating_add(1);
        return TrackedArrival {
            track,
            settled: None,
        };
    }
    if let Some(index) = track.gaps.iter().position(|g| g.generation == generation) {
        track.gaps.remove(index);
        return TrackedArrival {
            track,
            settled: None,
        };
    }
    let settled = track
        .told
        .iter()
        .position(|g| g.generation == generation)
        .map(|index| track.told.remove(index).notice);
    TrackedArrival { track, settled }
}

/// The gaps open for at least `MISSING_MESSAGE_GRACE_MS` at `now_ms`: they
/// move to `told` under `notice` (the id of the one notice the app shows
/// for them) and come back as `due`, oldest first.
#[uniffi::export]
pub fn due_generations(track: GenerationTrack, now_ms: i64, notice: String) -> DueGenerations {
    let grace = MISSING_MESSAGE_GRACE_MS as i64;
    let (due, open): (Vec<_>, Vec<_>) = track
        .gaps
        .iter()
        .cloned()
        .partition(|g| now_ms.saturating_sub(g.at) >= grace);
    if due.is_empty() {
        return DueGenerations { track, due };
    }
    let mut told = track.told;
    told.extend(due.iter().map(|g| ToldGeneration {
        generation: g.generation,
        notice: notice.clone(),
    }));
    DueGenerations {
        track: GenerationTrack {
            user_id: track.user_id,
            next: track.next,
            gaps: open,
            told,
        },
        due,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> GenerationTrack {
        GenerationTrack {
            user_id: "u_alice".into(),
            next: 0,
            gaps: Vec::new(),
            told: Vec::new(),
        }
    }

    #[test]
    fn a_far_jump_opens_at_most_the_forward_limit() {
        let arrival = track_generation(fresh(), 1000, 5, 9);
        assert_eq!(arrival.track.next, 1001);
        assert_eq!(arrival.track.gaps.len(), MAX_GENERATION_GAP as usize);
        assert_eq!(arrival.track.gaps[0].generation, 800);
        assert_eq!(arrival.track.gaps[199].generation, 999);
        assert!(arrival
            .track
            .gaps
            .iter()
            .all(|g| g.at == 5 && g.before == 8));
    }

    #[test]
    fn a_late_told_message_settles_its_notice_once() {
        let track = track_generation(fresh(), 3, 0, 0).track;
        let told = due_generations(track, 120_000, "n1".into());
        assert_eq!(
            told.due.iter().map(|g| g.generation).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert!(told.track.gaps.is_empty());
        // Not yet due a millisecond before the grace time ends.
        let early = due_generations(
            track_generation(fresh(), 1, 1, 1).track,
            120_000,
            "n2".into(),
        );
        assert!(early.due.is_empty());
        let late = track_generation(told.track, 1, 200_000, 200_000);
        assert_eq!(late.settled.as_deref(), Some("n1"));
        let again = track_generation(late.track, 1, 200_001, 200_001);
        assert_eq!(again.settled, None);
        assert_eq!(again.track.told.len(), 2);
    }

    #[test]
    fn the_top_generation_does_not_overflow() {
        let arrival = track_generation(fresh(), u32::MAX, 0, i64::MIN);
        assert_eq!(arrival.track.next, u32::MAX);
        assert_eq!(arrival.track.gaps.len(), MAX_GENERATION_GAP as usize);
        assert_eq!(arrival.track.gaps[0].before, i64::MIN);
        let due = due_generations(arrival.track, i64::MAX, "n".into());
        assert_eq!(due.due.len(), MAX_GENERATION_GAP as usize);
    }
}
