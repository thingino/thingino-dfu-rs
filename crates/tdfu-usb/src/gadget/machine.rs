//! U-Boot's DFU state machine and DFU core, modelled from their own source.
//!
//! Two layers, kept apart here exactly as they are on the device, because their
//! separation is the whole reason the stale-transaction retry exists:
//!
//! * **`f_dfu`** (`drivers/usb/gadget/f_dfu.c`) — the DFU 1.1 state machine. One
//!   function per state, dispatched through a table indexed by the current state
//!   (`f_dfu.c:623-635`). `DFU_ABORT`, `DFU_CLRSTATUS`, an alt switch and a bus reset
//!   all return it to `dfuIDLE`.
//! * **the DFU core** (`drivers/dfu/dfu.c`) — the per-entity transaction: a block
//!   sequence counter, a 2 MiB buffer and a medium offset. **It does not follow the
//!   state machine back to idle.** A host that walks away from a transfer and starts
//!   fresh has its block 0 refused with `Wrong sequence number!` (`dfu.c:384-390`,
//!   `:508-517`) unless the loader carries the `f_dfu_abort_transaction` fix
//!   (`f_dfu.c:314-331`, u-boot `3d4848fe0dc`).
//!
//! Every behaviour below carries the `file:line` it was read from. The C host tool is
//! not the authority here and is not cited: a device model is checked against the
//! device's own source, not against what the
//! host expects.

use super::descriptors;
use super::{AltConfig, AltKind, Event, GadgetConfig, Loader};

/// `XBURST_ERASE_TOKEN` (`arch/mips/mach-xburst/dfu.c:108`).
pub(super) const ERASE_TOKEN: &[u8] = b"XBURST-FLASH-WIPE";
/// `XBURST_REBOOT_TOKEN` (`arch/mips/mach-xburst/dfu.c:109`).
pub(super) const REBOOT_TOKEN: &[u8] = b"XBURST-REBOOT";

/// `DFU_POLL_TIMEOUT_MASK` (`f_dfu.h:84`): `bwPollTimeout` is a 24-bit field, and a
/// value that does not fit is reported as **zero**, not truncated (`f_dfu.c:141-147`).
const POLL_TIMEOUT_MASK: u32 = 0x00FF_FFFF;

/// `DFU_STATUS_OK` (DFU 1.1 §6.1.2).
pub(super) const STATUS_OK: u8 = 0;
/// `DFU_STATUS_errUNKNOWN` — what a failed `dfu_write` records (`f_dfu.c:164`).
pub(super) const STATUS_ERR_UNKNOWN: u8 = 14;

/// The DFU 1.1 device states, numbered as `enum dfu_state` numbers them.
///
/// The numbering is the dispatch table's index (`f_dfu.c:623-635`), so it is not free
/// to change: `bState` in a `GETSTATUS` reply and the single byte a `GETSTATE` reply
/// carries are both this number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DfuState {
    /// `DFU_STATE_appIDLE` — runtime mode.
    AppIdle,
    /// `DFU_STATE_appDETACH`.
    AppDetach,
    /// `DFU_STATE_dfuIDLE` — where every operation starts and ends.
    DfuIdle,
    /// `DFU_STATE_dfuDNLOAD_SYNC` — a block arrived; `GETSTATUS` moves on.
    DnloadSync,
    /// `DFU_STATE_dfuDNBUSY`.
    DnBusy,
    /// `DFU_STATE_dfuDNLOAD_IDLE` — mid-download, ready for the next block.
    DnloadIdle,
    /// `DFU_STATE_dfuMANIFEST_SYNC` — the zero-length `DNLOAD` landed.
    ManifestSync,
    /// `DFU_STATE_dfuMANIFEST` — held while the deferred flush is pending.
    Manifest,
    /// `DFU_STATE_dfuMANIFEST_WAIT_RST` — **not dispatchable**; see [`dispatch`].
    ManifestWaitReset,
    /// `DFU_STATE_dfuUPLOAD_IDLE` — mid-upload.
    UploadIdle,
    /// `DFU_STATE_dfuERROR` — serves three requests and stalls everything else.
    Error,
}

impl DfuState {
    /// The `bState` byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::AppIdle => 0,
            Self::AppDetach => 1,
            Self::DfuIdle => 2,
            Self::DnloadSync => 3,
            Self::DnBusy => 4,
            Self::DnloadIdle => 5,
            Self::ManifestSync => 6,
            Self::Manifest => 7,
            Self::ManifestWaitReset => 8,
            Self::UploadIdle => 9,
            Self::Error => 10,
        }
    }
}

/// DFU class request numbers (`f_dfu.h`, DFU 1.1 §3).
///
/// A duplicate of `tdfu_core::dfu::host::request` by necessity — `tdfu-core` depends on
/// this crate, so the dependency cannot run the other way — and both cite the same
/// header. They are the *device's* numbers here.
pub mod request {
    /// `USB_REQ_DFU_DETACH`.
    pub const DETACH: u8 = 0;
    /// `USB_REQ_DFU_DNLOAD`.
    pub const DNLOAD: u8 = 1;
    /// `USB_REQ_DFU_UPLOAD`.
    pub const UPLOAD: u8 = 2;
    /// `USB_REQ_DFU_GETSTATUS`.
    pub const GETSTATUS: u8 = 3;
    /// `USB_REQ_DFU_CLRSTATUS`.
    pub const CLRSTATUS: u8 = 4;
    /// `USB_REQ_DFU_GETSTATE`.
    pub const GETSTATE: u8 = 5;
    /// `USB_REQ_DFU_ABORT`.
    pub const ABORT: u8 = 6;
}

/// What a state function decided (`f_dfu.h:51-52`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Answer {
    /// `RET_STALL` — the endpoint stalls and the host sees a pipe error.
    Stall,
    /// `RET_ZLP` — an empty status stage.
    Zlp,
    /// A data stage. The transport truncates it to `min(wLength, transfer_size)`, as
    /// `f_dfu.c:669` and the USB stack between them do.
    Data(Vec<u8>),
    /// The gadget left the bus while answering — `do_reset()` from a reboot flush
    /// (`arch/mips/mach-xburst/dfu.c:266`) never returns, so this request gets no answer
    /// at all: the poll's failure IS the reset.
    Gone,
}

/// `req->complete`, the callback that runs once the transfer's data stage is done.
///
/// It is cleared on every setup packet (`composite.c:1028` assigns
/// `composite_setup_complete` before dispatching), so a handler that wants one sets it
/// and nobody else's fires. The ordering is load-bearing twice over: a `DNLOAD`'s write
/// happens *after* the request is answered, so its failure surfaces on the next
/// `GETSTATUS` and never on the `DNLOAD` itself; and the manifest flush is armed *after*
/// the `dfuMANIFEST` status has already gone out, which is why the poll that follows the
/// zero-length `DNLOAD` is the one that starts the erase.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Completion {
    /// `dnload_request_complete` (`f_dfu.c:156-167`).
    Write { data: Vec<u8>, seq: u16 },
    /// `dnload_request_flush` (`f_dfu.c:169-173`).
    DeferFlush,
}

/// `struct f_dfu` (`f_dfu.c:30-45`).
#[derive(Debug)]
pub(super) struct Dfu {
    pub(super) altsetting: u8,
    pub(super) state: DfuState,
    pub(super) status: u8,
    /// `blk_seq_num`: the block number of the last request, **not** the entity's
    /// counter. The two are separate fields on the device and diverge exactly when
    /// the stale-transaction recovery is needed.
    pub(super) blk_seq_num: u16,
}

/// `struct dfu_entity` (`drivers/dfu/dfu.c`), reduced to the state a host can observe.
#[derive(Debug)]
pub(super) struct Entity {
    /// The name lives once, in [`AltConfig::name`](super::AltConfig::name), because
    /// that is what the string descriptor serves and the host matches on. A second copy
    /// here would be a second source of truth for the same byte.
    pub(super) kind: AltKind,
    /// `dfu->inited`.
    pub(super) inited: bool,
    /// `dfu->i_blk_seq_num` — **survives a USB reset**.
    pub(super) sequence: u16,
    /// `dfu->offset`, the medium write/read cursor.
    ///
    /// `dfu_transaction_cleanup` sets it back to 0 (`dfu.c:294`), so a fresh
    /// transaction always restarts at the beginning of the medium. An earlier
    /// emulator made it monotone, which put every retry after a partial write at the
    /// wrong offset and made a whole class of test unwritable.
    pub(super) offset: u64,
    /// The DFU buffer's fill (`i_buf - i_buf_start`), as bytes.
    pub(super) buffer: Vec<u8>,
    /// `dfu->r_left`.
    pub(super) left: u64,
    /// The medium's written prefix; anything past it reads as erased (`0xFF`).
    pub(super) medium: Vec<u8>,
    /// `xburst_erase_armed` / `xburst_reboot_armed`
    /// (`arch/mips/mach-xburst/dfu.c:119`, `:124`).
    pub(super) armed: bool,
    /// `dfu->poll_timeout`, installed by `dfu_initiated_callback` for a virt entity
    /// (`arch/mips/mach-xburst/dfu.c:278-285`) and NULL for everything else.
    pub(super) poll_timeout_ms: u32,
}

impl Entity {
    fn new(alt: &AltConfig) -> Self {
        Self {
            kind: alt.kind,
            inited: false,
            sequence: 0,
            offset: 0,
            buffer: Vec::new(),
            left: 0,
            medium: Vec::new(),
            armed: false,
            poll_timeout_ms: 0,
        }
    }

    /// The medium's declared size — what `get_medium_size` reports at the start of a
    /// read (`dfu.c:338`).
    const fn size(&self) -> u64 {
        match self.kind {
            AltKind::Flash { size } => size,
            // A virt entity has no medium to read.
            AltKind::Erase | AltKind::Reboot => 0,
        }
    }
}

/// The whole emulated device: USB state, `f_dfu` state, and one entity per alt.
#[derive(Debug)]
pub(super) struct Device {
    pub(super) config: GadgetConfig,
    pub(super) configuration: Option<u8>,
    pub(super) claim: Option<crate::types::InterfaceSpec>,
    pub(super) dfu: Dfu,
    pub(super) entities: Vec<Entity>,
    /// `dfu_defer_flush` (`f_dfu.c:47`): the entity whose flush the gadget's main loop
    /// still owes. Held across polls, and `state_dfu_manifest` reports `dfuMANIFEST`
    /// for as long as it is set (`f_dfu.c:530-533`).
    pub(super) defer_flush: Option<usize>,
    /// How many more `GETSTATUS` answers see the deferred flush still pending.
    ///
    /// The device's answer is "however long the main loop takes"; a test double needs a
    /// number, so this is the discretisation. `common/dfu.c:70-88` clears the defer only
    /// *after* `dfu_flush` returns, which is what holds `dfuMANIFEST` for the duration
    /// of a whole-chip erase.
    pub(super) manifest_polls_left: usize,
    pending: Option<Completion>,
    /// EP0 answers nothing for this many more control requests.
    pub(super) silent: usize,
    pub(super) wedged: bool,
    /// The gadget has left the bus — `do_reset()` from a reboot flush
    /// (`arch/mips/mach-xburst/dfu.c:260-268`), or a `DETACH` that ended the main loop.
    pub(super) gone: bool,
    pub(super) events: Vec<Event>,
    pub(super) resets: usize,
    pub(super) wrong_sequence: usize,
    pub(super) flushes: usize,
    pub(super) erases: usize,
    pub(super) reboots: usize,
}

impl Device {
    pub(super) fn new(config: GadgetConfig) -> Self {
        let entities = config.alts.iter().map(Entity::new).collect();
        Self {
            config,
            configuration: None,
            claim: None,
            dfu: Dfu {
                altsetting: 0,
                // `dfu_bind` ends with `to_dfu_mode`, which is what puts a freshly bound
                // gadget in dfuIDLE rather than appIDLE (`f_dfu.c:763`, `:782`, `:230`).
                state: DfuState::DfuIdle,
                status: STATUS_OK,
                blk_seq_num: 0,
            },
            entities,
            defer_flush: None,
            manifest_polls_left: 0,
            pending: None,
            silent: 0,
            wedged: false,
            gone: false,
            events: Vec::new(),
            resets: 0,
            wrong_sequence: 0,
            flushes: 0,
            erases: 0,
            reboots: 0,
        }
    }

    /// The index of the entity the current alt selects.
    ///
    /// `dfu_get_entity(f_dfu->altsetting)` answers NULL for an alt that does not exist,
    /// and `f_dfu_abort_transaction` is the one caller that checks (`f_dfu.c:329`).
    fn current(&self) -> Option<usize> {
        let index = usize::from(self.dfu.altsetting);
        (index < self.entities.len()).then_some(index)
    }

    /// `f_dfu_abort_transaction` (`f_dfu.c:325-331`) — **only on a fixed loader**.
    ///
    /// Loaders carrying u-boot `3d4848fe0dc` clean the entity on
    /// `DFU_ABORT`, `DFU_CLRSTATUS` and every alt switch (which covers a bus reset,
    /// because the composite layer calls `set_alt` on every `SET_CONFIGURATION`); older
    /// loaders clean it only when a transaction completes or when an in-band sequence
    /// mismatch refuses a block. That difference is the whole of the
    /// stale-transaction case and of the erase close-out's two branches.
    fn abort_transaction(&mut self) {
        if self.config.loader == Loader::Legacy {
            return;
        }
        let Some(index) = self.current() else { return };
        self.transaction_abort(index);
    }

    /// `dfu_transaction_abort` (`dfu.c:315-321`): a no-op unless a transaction is open.
    fn transaction_abort(&mut self, index: usize) {
        if !self.entities[index].inited {
            return;
        }
        self.transaction_cleanup(index);
    }

    /// `dfu_transaction_cleanup` (`dfu.c:290-304`).
    ///
    /// Note what it does **not** clear: the virt entity's arming. Only
    /// `dfu_error_callback` and the flush itself do that
    /// (`arch/mips/mach-xburst/dfu.c:240`, `:264`, `:290-296`).
    fn transaction_cleanup(&mut self, index: usize) {
        let entity = &mut self.entities[index];
        entity.offset = 0;
        entity.sequence = 0;
        entity.buffer.clear();
        entity.left = 0;
        entity.inited = false;
    }

    /// `dfu_transaction_initiate` (`dfu.c:323-348`).
    fn transaction_initiate(&mut self, index: usize, read: bool) {
        if self.entities[index].inited {
            return;
        }
        self.transaction_cleanup(index);
        let virt_timeout = self.config.virt_poll_timeout_ms;
        let entity = &mut self.entities[index];
        if read {
            entity.left = entity.size();
        }
        entity.inited = true;
        // `dfu_initiated_callback` (`arch/mips/mach-xburst/dfu.c:278-285`): a virt
        // entity gains the 500 ms poll pace and a `flush_medium`, both of which must be
        // in place before the manifest phase reads them.
        entity.poll_timeout_ms = if descriptors::is_virtual(&entity.kind) {
            virt_timeout
        } else {
            0
        };
    }

    /// `dfu_error_callback` (`arch/mips/mach-xburst/dfu.c:290-296`): a failed
    /// transaction drops the arming, so a stale token cannot erase or reboot on some
    /// later flush.
    ///
    /// **The failing entity selects, and then BOTH armings go.** `xburst_erase_armed`
    /// and `xburst_reboot_armed` are two module-level statics (`:119`, `:124`), and the
    /// callback clears them together for any entity whose `dev_type` is `DFU_DEV_VIRT`:
    ///
    /// ```c
    /// if (dfu->dev_type == DFU_DEV_VIRT) {
    ///         xburst_erase_armed = false;
    ///         xburst_reboot_armed = false;
    /// }
    /// ```
    ///
    /// So a bad token on `erase` disarms a `reboot` that was already armed, and vice
    /// versa. Modelling it per-entity — which is what this did until the 2026-08-23
    /// audit — hid a whole class of device behaviour: the arming a host thinks it holds
    /// can be dropped by a transaction on the *other* virt alt.
    ///
    /// A failing **non**-virt entity (the flash) clears nothing, because the guard is on
    /// `dev_type` and not on which entity happens to be armed.
    fn error_callback(&mut self, index: usize) {
        if !descriptors::is_virtual(&self.entities[index].kind) {
            return;
        }
        for entity in &mut self.entities {
            if descriptors::is_virtual(&entity.kind) {
                entity.armed = false;
            }
        }
    }

    /// `dfu_write_buffer_drain` (`dfu.c:261-288`).
    ///
    /// An empty buffer writes nothing at all (`:268-269`) — which matters for the
    /// zero-length `DNLOAD` that ends a transfer whose last block exactly filled the
    /// buffer. `i_buf` is reset and `offset` advances whether or not the medium write
    /// succeeded.
    fn buffer_drain(&mut self, index: usize) -> Result<(), ()> {
        let size = self.entities[index].buffer.len();
        if size == 0 {
            return Ok(());
        }
        let buffer = core::mem::take(&mut self.entities[index].buffer);
        let offset = self.entities[index].offset;
        let outcome = self.write_medium(index, offset, &buffer);
        self.entities[index].offset += size as u64;
        self.flushes += 1;
        // The drain runs inside the `DNLOAD`'s completion handler, in the UDC's
        // interrupt context: EP0 answers nothing until it returns. That is the
        // 2 MiB stall and the reason the write grace exists at all.
        //
        // **The two silences are not the same silence, and this models them as one.**
        // A drain from here is irq context and EP0 is dead for its duration; a drain
        // from the *deferred* flush is thread context, and `common/dfu.c:81` pumps the
        // UDC's interrupts on the way in — so a whole-chip erase answers some polls
        // while it runs, which is exactly why the fork's `dfuMANIFEST` hold exists
        // for a virt entity. One knob covers both because no operation distinguishes
        // them: both look like "the poll did not come back" to a host, and the grace
        // tiers are sized for the worse of the two. Recorded rather than modelled
        // separately, so nobody reads the equality as a claim about the device.
        self.silent += self.config.flush_silence_polls;
        outcome
    }

    /// The entity backends' `write_medium`.
    ///
    /// `dfu_sf`/`dfu_mtd` write bytes; the two virt entities validate a token and arm
    /// (`arch/mips/mach-xburst/dfu.c:203-226`). The virt check is a **length floor plus a
    /// prefix compare**, not an exact-length compare: `offset != 0 || *len < strlen(tok)
    /// || memcmp(buf, tok, strlen(tok))`. A longer buffer that starts with the token
    /// arms just as well.
    fn write_medium(&mut self, index: usize, offset: u64, data: &[u8]) -> Result<(), ()> {
        let entity = &mut self.entities[index];
        match entity.kind {
            AltKind::Flash { size } => {
                let end = offset.saturating_add(data.len() as u64);
                if end > size {
                    return Err(());
                }
                let start = usize::try_from(offset).map_err(|_| ())?;
                // `cargo mutants` reports `<` -> `<=` here as surviving, and it is an
                // equivalent mutant: the extra case is `len == start + data.len()`, where
                // the resize is to the length the vector already has. Nothing can
                // separate them.
                if entity.medium.len() < start + data.len() {
                    entity.medium.resize(start + data.len(), 0xFF);
                }
                entity.medium[start..start + data.len()].copy_from_slice(data);
                Ok(())
            }
            AltKind::Erase => arm(entity, offset, data, ERASE_TOKEN),
            AltKind::Reboot => arm(entity, offset, data, REBOOT_TOKEN),
        }
    }

    /// The entity backends' `flush_medium`, called from the deferred `dfu_flush` in the
    /// gadget's main loop — never from the interrupt context the write runs in
    /// (`arch/mips/mach-xburst/dfu.c:111-118`).
    fn flush_medium(&mut self, index: usize) -> Result<(), ()> {
        match self.entities[index].kind {
            AltKind::Flash { .. } => Ok(()),
            AltKind::Erase => {
                // `xburst_erase_flush` (`:233-253`). **The unarmed case returns success
                // having erased nothing** — which is the device shape the
                // blank check exists to catch.
                if !core::mem::take(&mut self.entities[index].armed) {
                    return Ok(());
                }
                // The whole boot flash, whichever alt armed the erase (`:247-250`; alt 0
                // is the boot flash). A gadget with no flash entity at
                // all prints "dfu erase: no boot flash detected" and returns -ENODEV
                // (`:251-252`), which ends the gadget's main loop rather than reporting
                // through DFU status.
                let Some(flash) = self
                    .entities
                    .iter_mut()
                    .find(|entity| matches!(entity.kind, AltKind::Flash { .. }))
                else {
                    return Err(());
                };
                flash.medium.clear();
                self.erases += 1;
                Ok(())
            }
            AltKind::Reboot => {
                // `xburst_reboot_flush` (`:260-268`): `do_reset()` never returns, so the
                // request that triggered it is never answered: the poll's
                // failure IS the reset.
                if !core::mem::take(&mut self.entities[index].armed) {
                    return Ok(());
                }
                self.reboots += 1;
                self.gone = true;
                Ok(())
            }
        }
    }

    /// `dfu_flush` (`dfu.c:350-370`): drain, flush the medium, clean the transaction.
    fn flush(&mut self, index: usize) -> Result<(), ()> {
        self.buffer_drain(index)?;
        let outcome = self.flush_medium(index);
        self.transaction_cleanup(index);
        outcome
    }

    /// The gadget's main loop taking one turn at the flush it still owes
    /// (`common/dfu.c:70-88`). `true` means the device left the bus.
    ///
    /// **The flush belongs to the loop, not to the state machine.**
    /// `dfu_set_defer_flush` is set from `dnload_request_flush` (`f_dfu.c:169-173`) and
    /// cleared only by `common/dfu.c:83`, *after* `dfu_flush` returns; `dfu_set_alt`
    /// does not touch it (`f_dfu.c:823-841`). So a host that walks out of dfuMANIFEST —
    /// and `SET_INTERFACE` is the only way out, because it forces dfuIDLE at `:837` —
    /// is still owed the flush, and the loop performs it at its next turn whatever DFU
    /// state the host has moved to.
    ///
    /// That window is not theoretical: `common/dfu.c:81` pumps the UDC's interrupts
    /// *inside* the `if (dfu_get_defer_flush())` branch, one line before the flush, so
    /// requests the host has already sent are serviced first. It is how the unarmed
    /// branch of a virt entity's `flush_medium` is reached at all — arm one virt alt,
    /// fail a transaction on the other (which drops **both** armings,
    /// [`error_callback`](Self::error_callback)), and the owed flush then runs having
    /// nothing to do.
    fn run_deferred_flush(&mut self) -> bool {
        let Some(index) = self.defer_flush.take() else {
            return false;
        };
        self.manifest_polls_left = 0;
        if self.flush(index).is_err() {
            // `common/dfu.c:84-87`: a deferred flush that fails ends the gadget's main
            // loop, so the device leaves the bus rather than reporting the failure
            // through DFU status.
            self.gone = true;
        }
        self.gone
    }

    /// `dfu_write` (`dfu.c:372-441`).
    fn write(&mut self, index: usize, data: &[u8], seq: u16) -> Result<(), ()> {
        self.transaction_initiate(index, false);

        if self.entities[index].sequence != seq {
            // `Wrong sequence number! [%d] [%d]` (`dfu.c:385-386`). The refusal itself
            // cleans the entity, which is why the host's *retry* of block 0 succeeds
            // even on a loader without the abort fix, at the cost of
            // exactly one benign console line.
            self.wrong_sequence += 1;
            self.transaction_cleanup(index);
            self.error_callback(index);
            return Err(());
        }
        // DFU 1.1's block number is 16-bit and rolls over at 0xFFFF — every 256 MiB at
        // a 4096-byte transfer size (`dfu.c:392-406`). Nothing in this model may treat
        // `block == 0` as "a new transaction".
        self.entities[index].sequence = self.entities[index].sequence.wrapping_add(1);

        let size = data.len();
        let capacity = self.config.buffer_size;
        if self.entities[index].buffer.len() + size > capacity {
            self.drain_or_fail(index)?;
        }
        if self.entities[index].buffer.len() + size > capacity {
            // "Buffer overflow!" (`dfu.c:419-425`): one block larger than the whole
            // entity buffer. Unreachable while `transfer_size <= buffer_size`.
            self.transaction_cleanup(index);
            self.error_callback(index);
            return Err(());
        }
        self.entities[index].buffer.extend_from_slice(data);
        if size == 0 || self.entities[index].buffer.len() + size > capacity {
            self.drain_or_fail(index)?;
        }
        Ok(())
    }

    /// The `dfu_write` drain sites, which clean up and disarm on failure
    /// (`dfu.c:410-415`, `:432-437`).
    fn drain_or_fail(&mut self, index: usize) -> Result<(), ()> {
        if self.buffer_drain(index).is_ok() {
            return Ok(());
        }
        self.transaction_cleanup(index);
        self.error_callback(index);
        Err(())
    }

    /// `dfu_read` (`dfu.c:497-537`).
    ///
    /// Note the asymmetry with [`write`](Self::write): a wrong sequence number here
    /// cleans the transaction but calls **no** error callback (`dfu.c:508-517`), and the
    /// failure reaches the host as a stalled `UPLOAD` rather than as `dfuERROR`.
    // Model note: the device advances `dfu->offset` in whole
    // `dfu_get_buf_size()` fills with `b_left` holding the remainder (`dfu.c:473-488`);
    // this collapses it to the host-visible cursor. Host-visible behaviour is identical;
    // `entity_offset` after a PARTIAL read is not - and an earlier emulator's worst
    // defect was an offset bug, so say it here rather than let a reader assume
    // equivalence.
    fn read(&mut self, index: usize, len: u16, seq: u16) -> Result<Vec<u8>, ()> {
        self.transaction_initiate(index, true);

        if self.entities[index].sequence != seq {
            self.wrong_sequence += 1;
            self.transaction_cleanup(index);
            return Err(());
        }
        self.entities[index].sequence = self.entities[index].sequence.wrapping_add(1);

        let want = u64::from(len);
        let entity = &mut self.entities[index];
        let take = usize::try_from(want.min(entity.left)).map_err(|_| ())?;
        let start = usize::try_from(entity.offset).map_err(|_| ())?;
        let data: Vec<u8> = (start..start + take)
            .map(|at| entity.medium.get(at).copied().unwrap_or(0xFF))
            .collect();
        entity.offset += take as u64;
        entity.left -= take as u64;

        // A short block is how an upload ends (`dfu.c:527-534`); the entity is cleaned
        // and `state_dfu_upload_idle` drops back to dfuIDLE (`f_dfu.c:568-569`).
        if take < usize::from(len) {
            self.transaction_cleanup(index);
        }
        Ok(data)
    }

    /// `dfu_set_poll_timeout` (`f_dfu.c:127-152`).
    ///
    /// Zero, and **anything that does not fit in 24 bits**, is reported as three zero
    /// bytes. A model that truncated instead would make `<< 16` and `>> 16`
    /// indistinguishable in exactly the way mutation testing is there to catch.
    const fn poll_bytes(ms: u32) -> [u8; 3] {
        if ms == 0 || (ms & !POLL_TIMEOUT_MASK) != 0 {
            return [0, 0, 0];
        }
        let bytes = ms.to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    }

    /// `dfu_get_manifest_timeout` (`f_dfu.c:175-179`): the entity's own pace if it has
    /// one, else `DFU_MANIFEST_POLL_TIMEOUT`, which is `DFU_DEFAULT_POLL_TIMEOUT` and is
    /// **0** on every shipped loader (`include/dfu.h:121-125`).
    fn manifest_timeout(&self) -> u32 {
        self.current().map_or(0, |index| self.entities[index].poll_timeout_ms)
    }

    /// `handle_getstatus` (`f_dfu.c:181-215`).
    fn handle_getstatus(&mut self) -> Vec<u8> {
        let mut poll = 0;
        match self.dfu.state {
            DfuState::DnloadSync | DfuState::DnBusy => self.dfu.state = DfuState::DnloadIdle,
            // **Dead, on the device as well as here**, and modelled anyway for the reason
            // the `default_poll_timeout_ms` branch below is: `state_dfu_manifest_sync`
            // assigns dfuMANIFEST *before* it calls this (`f_dfu.c:494-495`), so by the
            // time the switch runs the state is already `Manifest` and this arm is never
            // taken. It is `f_dfu.c:194-196` and it is kept so the switch has the shape
            // the device gives it — a loader that reordered those two lines would need
            // it, and a mutant here cannot be killed. Knowing the difference between a
            // hole and an unkillable mutant is the whole of it.
            DfuState::ManifestSync => self.dfu.state = DfuState::Manifest,
            DfuState::Manifest => poll = self.manifest_timeout(),
            _ => {}
        }

        // `f_dfu->poll_timeout` is `DFU_DEFAULT_POLL_TIMEOUT` (`f_dfu.c:880`), which is
        // 0 on every shipped loader, so this branch is dead there. Modelled anyway
        // because it is the only place the *entity buffer* enters a status reply, and
        // because of the divide-by-zero landmine it carries when
        // `DFU_USB_BUFSIZ` exceeds the buffer — guarded here rather than reproduced.
        if self.config.default_poll_timeout_ms != 0 {
            let blocks = self.config.buffer_size / usize::from(self.config.transfer_size.max(1));
            if blocks != 0 && usize::from(self.dfu.blk_seq_num) % blocks == 0 {
                poll = self.config.default_poll_timeout_ms;
            }
        }

        let [lo, mid, hi] = Self::poll_bytes(poll);
        vec![self.dfu.status, lo, mid, hi, self.dfu.state.code(), 0]
    }

    /// `handle_getstate` (`f_dfu.c:217-223`).
    fn handle_getstate(&self) -> Vec<u8> {
        vec![self.dfu.state.code()]
    }

    /// `handle_upload` (`f_dfu.c:240-246`).
    ///
    /// It reads **`req->length`, not `wLength`** — and `composite_setup` re-initialises
    /// `req->length` to `USB_BUFSIZ` on every setup packet (`composite.c:1029`,
    /// `composite.c:17`). So the device lifts a whole `USB_BUFSIZ` off the medium and
    /// the USB stack then truncates the answer to `wLength`: a host that asks for less
    /// than 4096 gets less **and the device's read cursor still advances 4096**. It is
    /// invisible on hardware because `USB_BUFSIZ` and `DFU_USB_BUFSIZ` are both 4096,
    /// and it is modelled rather than smoothed over because a double that quietly
    /// disagrees with its device removes coverage in silence.
    fn handle_upload(&mut self) -> Result<Vec<u8>, ()> {
        let index = self.current().ok_or(())?;
        let seq = self.dfu.blk_seq_num;
        let want = self.config.usb_bufsiz;
        self.read(index, want, seq)
    }

    /// `handle_dnload` (`f_dfu.c:248-260`).
    fn handle_dnload(&mut self, data: &[u8]) -> usize {
        if data.is_empty() {
            self.dfu.state = DfuState::ManifestSync;
        }
        self.pending = Some(Completion::Write {
            data: data.to_vec(),
            seq: self.dfu.blk_seq_num,
        });
        data.len()
    }

    /// Run whatever `req->complete` was set to, once the transfer is done.
    fn run_completion(&mut self) {
        match self.pending.take() {
            None => {}
            Some(Completion::Write { data, seq }) => {
                // `dnload_request_complete` (`f_dfu.c:156-167`).
                //
                // An alt with no entity behind it is a NULL dereference on the device
                // (`dfu_get_entity` answers NULL and `dfu_write` walks straight into
                // it), and `handle_upload` has the same hole. A double must not model
                // undefined behaviour, and of the two defined answers — silently succeed
                // or fail — failing is the one no operation can misread. It matches the
                // upload path, which already stalls.
                let failed = match self.current() {
                    Some(index) => self.write(index, &data, seq).is_err(),
                    None => true,
                };
                if failed {
                    self.dfu.status = STATUS_ERR_UNKNOWN;
                    self.dfu.state = DfuState::Error;
                }
            }
            Some(Completion::DeferFlush) => {
                // `dnload_request_flush` (`f_dfu.c:169-173`).
                self.defer_flush = self.current();
                self.manifest_polls_left = self.config.manifest_hold_polls;
            }
        }
    }
}

/// `arch/mips/mach-xburst/dfu.c:203-226` — validate the token and arm.
fn arm(entity: &mut Entity, offset: u64, data: &[u8], token: &[u8]) -> Result<(), ()> {
    if offset != 0 || data.len() < token.len() || &data[..token.len()] != token {
        return Err(());
    }
    entity.armed = true;
    Ok(())
}

/// One DFU class request, as the state machine sees it.
pub(super) struct Ctrl<'a> {
    /// `bRequest`.
    pub(super) request: u8,
    /// `wValue` — the block number for `DNLOAD` and `UPLOAD`.
    pub(super) value: u16,
    /// `wLength`, already clamped to `DFU_USB_BUFSIZ` by the caller.
    pub(super) len: u16,
    /// The OUT data stage, empty for an IN request.
    pub(super) data: &'a [u8],
    /// Whether `bmRequestType` has `USB_DIR_IN` set.
    pub(super) dir_in: bool,
}

/// `dfu_handle`'s class-request half (`f_dfu.c:665-666`) plus the completion that runs
/// after it.
///
/// The standard-request half is not here: `GET_DESCRIPTOR` for the device,
/// configuration and string descriptors is answered by the composite layer before a
/// function's `setup` is ever called, and the one standard request `f_dfu` does handle
/// — `GET_DESCRIPTOR` of the DFU functional descriptor (`f_dfu.c:659-664`) — is served
/// by the transport directly.
pub(super) fn dispatch(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    // `composite.c:1028` reassigns `req->complete` on every setup packet, so a stale
    // callback from the previous request can never fire.
    device.pending = None;

    // The gadget's main loop gets a turn between requests. While the host is still
    // polling in dfuMANIFEST, `state_dfu_manifest` owns that turn — the poll *is* the
    // loop's pace there — but an owed flush outlives dfuMANIFEST, because
    // `dfu_set_alt` clears the state and not `dfu_defer_flush`. See
    // [`Device::run_deferred_flush`].
    if !matches!(device.dfu.state, DfuState::Manifest) && device.defer_flush.is_some() {
        if device.manifest_polls_left > 0 {
            device.manifest_polls_left -= 1;
        } else if device.run_deferred_flush() {
            return Answer::Gone;
        }
    }

    let answer = match device.dfu.state {
        DfuState::AppIdle => state_app_idle(device, ctrl),
        DfuState::AppDetach => state_app_detach(device, ctrl),
        DfuState::DfuIdle => state_dfu_idle(device, ctrl),
        DfuState::DnloadSync => state_dfu_dnload_sync(device, ctrl),
        DfuState::DnBusy => state_dfu_dnbusy(device, ctrl),
        DfuState::DnloadIdle => state_dfu_dnload_idle(device, ctrl),
        DfuState::ManifestSync => state_dfu_manifest_sync(device, ctrl),
        // Model note: the device runs the deferred flush BETWEEN requests
        // (`common/dfu.c:81-88`); this runs it inside the GETSTATUS that answers
        // dfuIDLE. Equivalent for a normal flush; a FAILING one fails the triggering
        // request here where the device fails the next.
        DfuState::Manifest => state_dfu_manifest(device, ctrl),
        DfuState::UploadIdle => state_dfu_upload_idle(device, ctrl),
        DfuState::Error => state_dfu_error(device, ctrl),
        // `dfu_state[DFU_STATE_dfuMANIFEST_WAIT_RST]` is NULL (`f_dfu.c:632`), so a
        // class request in this state calls through a null pointer. Nothing here can
        // enter it — `state_dfu_idle`'s DETACH assigns it and overwrites it with appIDLE
        // two lines later (`f_dfu.c:386-389`) — and a double must not pretend to model
        // undefined behaviour, so this stalls and says so.
        DfuState::ManifestWaitReset => Answer::Stall,
    };
    device.run_completion();
    answer
}

/// `state_app_idle` (`f_dfu.c:264-289`).
///
/// **`DETACH` nets dfuIDLE, not appDETACH.** The assignment at `f_dfu.c:279` is
/// overwritten on the very next line: `to_dfu_mode(f_dfu)` (`:280`) ends with
/// `f_dfu->dfu_state = DFU_STATE_dfuIDLE` (`:230`), which is the whole point of the call
/// — a `DFU_DETACH` in runtime mode is what puts the function *into* DFU mode, swapping
/// its descriptors and strings with it. Modelling the intermediate value was a defect
/// with a test defending it: the emulator answered appDETACH to a `GETSTATE` the device
/// answers dfuIDLE to.
fn state_app_idle(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        request::DETACH => {
            device.dfu.state = DfuState::DfuIdle;
            Answer::Zlp
        }
        _ => Answer::Stall,
    }
}

/// `state_app_detach` (`f_dfu.c:291-312`) — note it falls **back to appIDLE** rather
/// than to dfuERROR.
///
/// **Unreachable, on the device as well as here**, and for the same reason
/// [`state_dfu_dnbusy`] is: `f_dfu.c:279` is the only assignment of
/// `DFU_STATE_appDETACH` in the tree and `to_dfu_mode` overwrites it one line later
/// (`:280`, `:230`). It is kept so the dispatch table has the shape `f_dfu.c:625` gives
/// it, and so a loader that stops calling `to_dfu_mode` there has a model waiting. A
/// mutant here cannot be killed, and that is a property of the device.
fn state_app_detach(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        _ => {
            device.dfu.state = DfuState::AppIdle;
            Answer::Stall
        }
    }
}

/// `state_dfu_idle` (`f_dfu.c:333-400`).
///
/// **There is no `CLRSTATUS` case.** A `CLRSTATUS` sent to an idle device falls to the
/// default arm, which stalls *and enters* dfuERROR — so the host layer's choice between
/// `ABORT` and `CLRSTATUS` is not a stylistic one.
fn state_dfu_idle(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::DNLOAD if !ctrl.dir_in => {
            if ctrl.len == 0 {
                // A transfer cannot *start* with the end-of-transfer trigger
                // (`f_dfu.c:347-351`).
                device.dfu.state = DfuState::Error;
                return Answer::Stall;
            }
            device.dfu.state = DfuState::DnloadSync;
            device.dfu.blk_seq_num = ctrl.value;
            device.handle_dnload(ctrl.data);
            Answer::Zlp
        }
        request::UPLOAD if ctrl.dir_in => {
            device.dfu.state = DfuState::UploadIdle;
            // The first block of an upload is block 0 by decree, whatever `wValue` said
            // (`f_dfu.c:360`).
            device.dfu.blk_seq_num = 0;
            upload(device, ctrl)
        }
        // A `DNLOAD` with the IN direction bit set, or an `UPLOAD` without it, matches
        // the inner `if` of neither arm and changes nothing (`f_dfu.c:345-365`): `value`
        // stays 0, so the device answers a bare ZLP. Unrepresentable through this
        // transport, where direction is the struct.
        request::DNLOAD | request::UPLOAD => Answer::Zlp,
        request::ABORT => {
            device.abort_transaction();
            Answer::Zlp
        }
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        request::DETACH => {
            // The proprietary "back to runtime mode" extension (`f_dfu.c:377-392`): it
            // assigns dfuMANIFEST_WAIT_RST and overwrites it with appIDLE two lines
            // later, which is the only reason that state is never dispatched.
            //
            // `g_dnl_trigger_detach` then makes the main loop leave *eventually* — it
            // pumps 10 000 more interrupt handles first (`common/dfu.c:58-64`), so the
            // device keeps answering in runtime mode for a while. This model keeps it
            // answering and does not simulate the eventual unbind; nothing in this tool
            // sends `DFU_DETACH`, and the states below exist for fidelity.
            device.dfu.state = DfuState::AppIdle;
            Answer::Zlp
        }
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// `state_dfu_dnload_sync` (`f_dfu.c:402-423`).
fn state_dfu_dnload_sync(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// `state_dfu_dnbusy` (`f_dfu.c:425-443`) — narrower still: not even `GETSTATE`.
///
/// **Unreachable, on the device as well as here.** Nothing in the U-Boot tree ever
/// assigns `DFU_STATE_dfuDNBUSY`: it appears only in `handle_getstatus`'s case arm
/// (`f_dfu.c:191`), in the dispatch table (`:628`) and in the enum (`f_dfu.h:59`). It is
/// kept so the dispatch table has the shape `f_dfu.c` gives it, and so a loader that
/// starts using the state has a model waiting. A mutant here cannot be killed, and that
/// is a property of the device, not a hole in the tests.
fn state_dfu_dnbusy(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    if ctrl.request == request::GETSTATUS {
        return Answer::Data(device.handle_getstatus());
    }
    device.dfu.state = DfuState::Error;
    Answer::Stall
}

/// `state_dfu_dnload_idle` (`f_dfu.c:445-482`).
fn state_dfu_dnload_idle(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::DNLOAD if !ctrl.dir_in => {
            // Unlike dfuIDLE, a zero-length DNLOAD here is the manifest trigger rather
            // than an error — `handle_dnload` sees the length.
            device.dfu.state = DfuState::DnloadSync;
            device.dfu.blk_seq_num = ctrl.value;
            device.handle_dnload(ctrl.data);
            Answer::Zlp
        }
        request::DNLOAD => Answer::Zlp,
        request::ABORT => {
            device.dfu.state = DfuState::DfuIdle;
            device.abort_transaction();
            Answer::Zlp
        }
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// `state_dfu_manifest_sync` (`f_dfu.c:484-509`).
///
/// The `GETSTATUS` that lands here does four things in this order: move to dfuMANIFEST,
/// build the reply *from that new state*, zero the block counter, and only then arm the
/// deferred flush. The host's poll is therefore what starts the erase, and the
/// post-ZLP poll is load-bearing for exactly this reason.
fn state_dfu_manifest_sync(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::GETSTATUS => {
            device.dfu.state = DfuState::Manifest;
            let reply = device.handle_getstatus();
            device.dfu.blk_seq_num = 0;
            device.pending = Some(Completion::DeferFlush);
            Answer::Data(reply)
        }
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// `state_dfu_manifest` (`f_dfu.c:511-549`).
///
/// The fork's change (`c413453`): while `dfu_get_defer_flush()` is set the
/// reply stays dfuMANIFEST and carries the entity's poll pace, so a host polling through
/// a whole-chip erase is told to keep waiting. Stock `f_dfu` reported dfuIDLE
/// mid-erase and the host let go after 0.6 s calling it success.
fn state_dfu_manifest(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::GETSTATUS => {
            if device.defer_flush.is_some() {
                if device.manifest_polls_left > 0 {
                    device.manifest_polls_left -= 1;
                    return Answer::Data(device.handle_getstatus());
                }
                // The gadget's main loop got there: `dfu_flush`, then clear the defer
                // (`common/dfu.c:81-88`). A reboot entity does not come back from this.
                if device.run_deferred_flush() {
                    return Answer::Gone;
                }
            }
            device.dfu.state = DfuState::DfuIdle;
            let reply = device.handle_getstatus();
            device.dfu.blk_seq_num = 0;
            Answer::Data(reply)
        }
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// `state_dfu_upload_idle` (`f_dfu.c:551-591`).
fn state_dfu_upload_idle(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::UPLOAD if ctrl.dir_in => {
            device.dfu.blk_seq_num = ctrl.value;
            upload(device, ctrl)
        }
        request::UPLOAD => Answer::Zlp,
        request::ABORT => {
            device.dfu.state = DfuState::DfuIdle;
            device.abort_transaction();
            Answer::Zlp
        }
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// `state_dfu_error` (`f_dfu.c:593-621`).
///
/// **Three requests, and everything else stalls — `ABORT` included, and the state stays
/// dfuERROR.** An earlier emulator served all three of `GETSTATUS`, `GETSTATE` and
/// `ABORT` here, which made the whole recovery class unfalsifiable: deleting
/// the host's `CLRSTATUS` branch passed all 448 tests.
fn state_dfu_error(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match ctrl.request {
        request::GETSTATUS => Answer::Data(device.handle_getstatus()),
        request::GETSTATE => Answer::Data(device.handle_getstate()),
        request::CLRSTATUS => {
            device.dfu.state = DfuState::DfuIdle;
            device.dfu.status = STATUS_OK;
            device.abort_transaction();
            Answer::Zlp
        }
        _ => {
            device.dfu.state = DfuState::Error;
            Answer::Stall
        }
    }
}

/// The shared tail of the two `UPLOAD` arms (`f_dfu.c:361-364`, `:567-570`).
///
/// A short answer drops the machine back to dfuIDLE; a refusal (a stale sequence
/// number) is a negative return, which `dfu_handle` turns into a stall without touching
/// the state (`f_dfu.c:668`).
fn upload(device: &mut Device, ctrl: &Ctrl<'_>) -> Answer {
    match device.handle_upload() {
        Err(()) => Answer::Stall,
        Ok(data) => {
            if data.len() < usize::from(ctrl.len) {
                device.dfu.state = DfuState::DfuIdle;
            }
            Answer::Data(data)
        }
    }
}

/// `dfu_set_alt` (`f_dfu.c:823-841`).
///
/// Called for a `SET_INTERFACE`, and by the composite layer for **every**
/// `SET_CONFIGURATION` with alt 0 — which is how a bus reset reaches the entity on a
/// fixed loader, and how USB 9.4.7's "every interface goes to alternate setting zero" is
/// satisfied. An earlier emulator left `current_alt` untouched by both.
pub(super) fn set_alt(device: &mut Device, alt: u8) {
    device.abort_transaction();
    device.dfu.altsetting = alt;
    device.dfu.state = DfuState::DfuIdle;
    device.dfu.status = STATUS_OK;
}
