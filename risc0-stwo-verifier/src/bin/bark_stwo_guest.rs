#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

// The RISC Zero guest target is RV32IM: it has one hart and intentionally has
// no RISC-V A extension. LLVM therefore lowers atomics used by RISC Zero,
// ark-relations, and foldhash to the compiler-rt ABI below. On this single-hart
// target, a strongest-order compiler fence plus volatile memory access provides
// the required observable behavior without weakening any STWO verification.
#[cfg(target_os = "zkvm")]
mod rv32im_atomic_abi {
    use core::ptr::{read_volatile, write_volatile};
    use core::sync::atomic::{compiler_fence, Ordering};

    #[inline]
    unsafe fn load<T: Copy>(ptr: *const T) -> T {
        compiler_fence(Ordering::SeqCst);
        let value = unsafe { read_volatile(ptr) };
        compiler_fence(Ordering::SeqCst);
        value
    }

    #[inline]
    unsafe fn store<T>(ptr: *mut T, value: T) {
        compiler_fence(Ordering::SeqCst);
        unsafe { write_volatile(ptr, value) };
        compiler_fence(Ordering::SeqCst);
    }

    #[no_mangle]
    unsafe extern "C" fn __atomic_load_1(ptr: *const u8, _order: i32) -> u8 {
        unsafe { load(ptr) }
    }

    #[no_mangle]
    unsafe extern "C" fn __atomic_store_1(ptr: *mut u8, value: u8, _order: i32) {
        unsafe { store(ptr, value) }
    }

    #[no_mangle]
    unsafe extern "C" fn __atomic_load_4(ptr: *const u32, _order: i32) -> u32 {
        unsafe { load(ptr) }
    }

    #[no_mangle]
    unsafe extern "C" fn __atomic_store_4(ptr: *mut u32, value: u32, _order: i32) {
        unsafe { store(ptr, value) }
    }

    // LLVM compiler-rt's size-specialized compare-exchange ABI omits the
    // source-level `weak` argument and is permitted to implement a strong CAS.
    #[no_mangle]
    unsafe extern "C" fn __atomic_compare_exchange_1(
        ptr: *mut u8,
        expected: *mut u8,
        desired: u8,
        _success_order: i32,
        _failure_order: i32,
    ) -> bool {
        let current = unsafe { load(ptr) };
        let expected_value = unsafe { load(expected) };
        if current == expected_value {
            unsafe { store(ptr, desired) };
            true
        } else {
            unsafe { store(expected, current) };
            false
        }
    }
}

#[cfg(target_os = "zkvm")]
fn main() {
    use bark_risc0_stwo_verifier::{upstream_stwo, BindingError, VerificationPolicy};

    // Independently reproduced by both checked-in STWO proofs. The RISC Zero
    // image ID authenticates these policy constants to the outer verifier.
    const PROGRAM_COMMITMENT: [u8; 32] = [
        0x4c, 0x75, 0x02, 0x3e, 0xf3, 0x74, 0x07, 0xbe, 0x73, 0x9a, 0x93, 0xea, 0xb0, 0xf1, 0x7f,
        0xf6, 0x24, 0xba, 0x71, 0x6e, 0x07, 0xef, 0xab, 0x79, 0x6a, 0xf5, 0x98, 0x46, 0x71, 0x4e,
        0xf0, 0x67,
    ];
    const STWO_POLICY_COMMITMENT: [u8; 32] = [
        0x62, 0x6c, 0xd3, 0x8f, 0x63, 0x85, 0x1c, 0x10, 0x67, 0xc7, 0xee, 0x15, 0x94, 0xae, 0x88,
        0x06, 0x94, 0x25, 0x53, 0x46, 0xc0, 0xa1, 0x79, 0xd6, 0x8c, 0x0b, 0xff, 0xf5, 0x71, 0x95,
        0x53, 0x14,
    ];
    const POLICY: VerificationPolicy =
        VerificationPolicy::new(PROGRAM_COMMITMENT, STWO_POLICY_COMMITMENT);

    let compressed_proof: Vec<u8> = env::read();
    let verified = upstream_stwo::verify_compressed_binary(&compressed_proof)
        .expect("STWO Cairo proof verification failed");
    let evidence = verified
        .verification_evidence_journal(&POLICY)
        .expect("verified STWO proof did not match the pinned program and policy");

    match verified.authorization_journal(&POLICY) {
        Ok(journal) => env::commit_slice(journal.as_bytes()),
        Err(
            BindingError::TransactionRelationInvalid
            | BindingError::ChainStateNotVerified
            | BindingError::OperatorTakeNotAuthorized,
        ) => env::commit_slice(evidence.as_bytes()),
        Err(error) => panic!("authorization policy mismatch: {error}"),
    }
}

#[cfg(not(target_os = "zkvm"))]
fn main() {
    panic!("bark-stwo-guest must be compiled for the RISC Zero zkVM target");
}
