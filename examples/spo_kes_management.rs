//! Stake Pool Operator KES Key Management
//!
//! This example demonstrates how an SPO should manage KES keys
//! for Cardano block production, including:
//! - Key generation
//! - Operational certificate creation
//! - KES period tracking and monitoring
//! - Key rotation warnings
//! - Block signing at specific periods
//!
//! This aligns with the workflow used in cardano-cli for SPO operations.
//!
//! Run with: cargo run --example spo_kes_management

use cardano_crypto::common::error::Result;
use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};
use cardano_crypto::kes::{KesAlgorithm, Sum6Kes};
use cardano_crypto::key::kes_period::{
    KES_SLOTS_PER_PERIOD_MAINNET, KESPeriodInfo, KesPeriod, is_kes_expired, kes_expiry_slot,
    kes_period_info, period_from_slot,
};
use cardano_crypto::key::operational_cert::OperationalCertificate;

/// Warning threshold: warn when fewer than this many periods remain
const ROTATION_WARNING_THRESHOLD: u32 = 10;

/// Critical threshold: urgent rotation needed
const ROTATION_CRITICAL_THRESHOLD: u32 = 3;

/// Print a separator line
fn separator() {
    println!("{}", "=".repeat(72));
}

/// Print a section header
fn section(title: &str) {
    println!("\n{}", title);
    println!("{}", "-".repeat(title.len()));
}

/// Display KES period status with color-coded warnings
fn display_kes_status(info: &KESPeriodInfo, ocert_start_period: KesPeriod) {
    let effective_remaining = if info.period.0 >= ocert_start_period.0 {
        info.total_periods
            .saturating_sub(info.period.0 - ocert_start_period.0)
    } else {
        info.total_periods
    };

    println!("  Current Period:    {}", info.period.0);
    println!("  OCert Start:       {}", ocert_start_period.0);
    println!("  Total Periods:     {}", info.total_periods);
    println!("  Remaining:         {}", effective_remaining);
    println!(
        "  Is Valid:          {}",
        if info.is_valid {
            "Yes"
        } else {
            "NO - EXPIRED!"
        }
    );

    // Rotation warnings
    if effective_remaining == 0 {
        println!("\n  [CRITICAL] KES KEY EXPIRED! Rotate immediately!");
        println!("             Blocks signed with this key will be INVALID!");
    } else if effective_remaining <= ROTATION_CRITICAL_THRESHOLD {
        println!(
            "\n  [CRITICAL] Only {} periods remaining! Rotate KES key NOW!",
            effective_remaining
        );
    } else if effective_remaining <= ROTATION_WARNING_THRESHOLD {
        println!(
            "\n  [WARNING] Only {} periods remaining. Plan rotation soon.",
            effective_remaining
        );
    } else {
        println!("\n  [OK] KES key is healthy.");
    }
}

/// Simulate SPO KES key management workflow
fn main() -> Result<()> {
    separator();
    println!("  STAKE POOL OPERATOR - KES KEY MANAGEMENT");
    separator();

    // =========================================================================
    // Step 1: Generate Cold Key (Done once, kept offline)
    // =========================================================================
    section("1. Pool Cold Key (Offline)");

    let cold_seed = [0x01u8; 32]; // In production: Use secure random seed!
    let cold_sk = Ed25519::gen_key(&cold_seed)?;
    let cold_vk = Ed25519::derive_verification_key(&cold_sk);

    println!(
        "  Cold verification key: {:02x?}...",
        &cold_vk.as_bytes()[..8]
    );
    println!("  [Security] Keep cold key OFFLINE in cold storage!");

    // =========================================================================
    // Step 2: Generate KES Signing Key
    // =========================================================================
    section("2. Generate KES Key (Hot Key)");

    let kes_seed = [0x02u8; 32]; // In production: Use secure random seed!
    let kes_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    let kes_vk = Sum6Kes::derive_verification_key(&kes_sk)?;

    let kes_vk_bytes = Sum6Kes::raw_serialize_verification_key_kes(&kes_vk);
    println!("  KES verification key: {:02x?}...", &kes_vk_bytes[..8]);
    println!("  KES algorithm:        Sum6Kes");
    println!("  Total periods:        {} (2^6)", Sum6Kes::total_periods());
    println!(
        "  Key lifetime:         ~{} days",
        (Sum6Kes::total_periods() * KES_SLOTS_PER_PERIOD_MAINNET) / (86400 / 20) // ~20 sec/slot
    );

    // =========================================================================
    // Step 3: Create Operational Certificate
    // =========================================================================
    section("3. Create Operational Certificate");

    // Simulate current blockchain state
    let current_slot: u64 = 80_000_000; // Example: ~4.5 years into mainnet
    let kes_start_slot = current_slot; // OCert starts now
    let ocert_counter = 5; // 6th operational certificate for this pool

    // Calculate KES period from slot
    let ocert_start_period = period_from_slot(kes_start_slot, KES_SLOTS_PER_PERIOD_MAINNET, 0);

    let ocert =
        OperationalCertificate::new(kes_vk.clone(), ocert_counter, ocert_start_period, &cold_sk);

    println!("  OCert Counter:        {}", ocert.counter());
    println!("  OCert KES Period:     {}", ocert.kes_period().0);
    println!("  OCert Start Slot:     {}", kes_start_slot);

    // Verify cold signature
    match ocert.verify(&cold_vk) {
        Ok(()) => println!("  Signature:            Valid (cold key authorized)"),
        Err(e) => println!("  Signature:            INVALID! {:?}", e),
    }

    // =========================================================================
    // Step 4: Check KES Period Status
    // =========================================================================
    section("4. Current KES Status");

    // Simulate being 20 periods into this KES key's lifetime
    let periods_elapsed = 20u32;
    let simulated_current_slot =
        kes_start_slot + (periods_elapsed as u64) * KES_SLOTS_PER_PERIOD_MAINNET;
    let current_period = period_from_slot(simulated_current_slot, KES_SLOTS_PER_PERIOD_MAINNET, 0);

    let info = kes_period_info::<Sum6Kes>(current_period);
    display_kes_status(&info, ocert_start_period);

    // =========================================================================
    // Step 5: Check Expiration
    // =========================================================================
    section("5. Expiration Check");

    let expiry_slot = kes_expiry_slot::<Sum6Kes>(KES_SLOTS_PER_PERIOD_MAINNET, kes_start_slot);
    let slots_until_expiry = expiry_slot.saturating_sub(simulated_current_slot);
    let days_until_expiry = slots_until_expiry / (86400 / 20); // ~20 sec/slot

    println!("  Expiry Slot:          {}", expiry_slot);
    println!("  Slots Until Expiry:   {}", slots_until_expiry);
    println!("  Days Until Expiry:    ~{}", days_until_expiry);

    let is_expired = is_kes_expired::<Sum6Kes>(
        simulated_current_slot,
        KES_SLOTS_PER_PERIOD_MAINNET,
        kes_start_slot,
    );
    println!(
        "  Status:               {}",
        if is_expired { "EXPIRED!" } else { "Active" }
    );

    // =========================================================================
    // Step 6: Sign a Block Header
    // =========================================================================
    section("6. Block Signing (Current Period)");

    // Evolve KES key to current period
    let mut evolved_sk = Sum6Kes::gen_key_kes_from_seed_bytes(&kes_seed)?;
    for p in 0..periods_elapsed {
        evolved_sk = Sum6Kes::update_kes(&(), evolved_sk, p as u64)?
            .expect("Should evolve within valid period");
    }

    let block_header = b"block_header_hash_abc123";
    let current_kes_period = periods_elapsed as u64;

    let sig = Sum6Kes::sign_kes(&(), current_kes_period, block_header, &evolved_sk)?;
    let sig_bytes = Sum6Kes::raw_serialize_signature_kes(&sig);

    println!("  Block Header:         {:?}...", &block_header[..16]);
    println!("  Signing Period:       {}", current_kes_period);
    println!("  Signature Size:       {} bytes", sig_bytes.len());

    // Verify signature
    match Sum6Kes::verify_kes(&(), &kes_vk, current_kes_period, block_header, &sig) {
        Ok(()) => println!("  Verification:         Success"),
        Err(e) => println!("  Verification:         FAILED! {:?}", e),
    }

    // =========================================================================
    // Step 7: Rotation Planning
    // =========================================================================
    section("7. Rotation Planning");

    let periods_remaining = Sum6Kes::total_periods() as u32 - periods_elapsed;
    let rotation_deadline_slot = kes_start_slot
        + ((Sum6Kes::total_periods() as u32 - ROTATION_CRITICAL_THRESHOLD) as u64)
            * KES_SLOTS_PER_PERIOD_MAINNET;

    println!("  Periods Remaining:    {}", periods_remaining);
    println!(
        "  Warning Threshold:    {} periods",
        ROTATION_WARNING_THRESHOLD
    );
    println!(
        "  Critical Threshold:   {} periods",
        ROTATION_CRITICAL_THRESHOLD
    );
    println!("  Rotate Before Slot:   {}", rotation_deadline_slot);

    if periods_remaining <= ROTATION_WARNING_THRESHOLD {
        println!("\n  ROTATION CHECKLIST:");
        println!("  [ ] Generate new KES key pair");
        println!("  [ ] Increment OCert counter (current: {})", ocert_counter);
        println!("  [ ] Sign new OCert with cold key");
        println!("  [ ] Update node with new KES key and OCert");
        println!("  [ ] Verify blocks are being produced");
        println!("  [ ] Securely delete old KES key");
    }

    // =========================================================================
    // Step 8: Demonstrate Critical Expiry Scenario
    // =========================================================================
    section("8. Critical Expiry Scenario");

    // Simulate being at period 61 (only 3 periods remaining)
    let critical_period = 61u32;
    let critical_info = kes_period_info::<Sum6Kes>(KesPeriod(critical_period));

    println!("  Simulating period {} (3 remaining):", critical_period);
    display_kes_status(&critical_info, ocert_start_period);

    // =========================================================================
    // Summary
    // =========================================================================
    separator();
    println!("  SUMMARY");
    separator();
    println!(
        "
  KES Key Management Best Practices:

  1. MONITOR: Check KES period status regularly (at least weekly)
  2. PLAN: Start rotation process when {} periods remain
  3. ROTATE: Complete rotation before {} periods remaining
  4. VERIFY: Always verify new OCert signature before deployment
  5. SECURE: Keep cold key offline, delete old KES keys after rotation

  Cardano Mainnet Parameters:
  - Slots per KES period: {} (~1.5 days)
  - Sum6Kes total periods: {} (~90 days)
  - Recommended rotation: Every 60-80 days
",
        ROTATION_WARNING_THRESHOLD,
        ROTATION_CRITICAL_THRESHOLD,
        KES_SLOTS_PER_PERIOD_MAINNET,
        Sum6Kes::total_periods()
    );

    separator();
    println!("  KES KEY MANAGEMENT EXAMPLE COMPLETE");
    separator();

    Ok(())
}
