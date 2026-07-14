#!/usr/bin/env python3
"""Attach constrained Garaga MSM hints to a deterministic Rust fixture.

Run with the Garaga 0.18.1 wheel built from commit
0e986ba5133c16a30ac86a7cd07c9551787d0e91. The verifier recomputes the BIP340
challenge and constrains every hint, so this generator is outside the trust
boundary.
"""

import hashlib
import json
import sys
from pathlib import Path

from garaga.definitions import BASE, CURVES, N_LIMBS, CurveID, G1Point
from garaga.hints.io import bigint_split, split_128
from garaga.starknet.tests_and_calldata_generators.msm import MSMCalldataBuilder

GARAGA_COMMIT = "0e986ba5133c16a30ac86a7cd07c9551787d0e91"
CURVE_ID = CurveID.SECP256K1


def tagged_challenge(rx: int, px: int, message_hash: int) -> int:
    tag_hash = hashlib.sha256(b"BIP0340/challenge").digest()
    preimage = (
        tag_hash
        + tag_hash
        + rx.to_bytes(32, "big")
        + px.to_bytes(32, "big")
        + message_hash.to_bytes(32, "big")
    )
    return int.from_bytes(hashlib.sha256(preimage).digest(), "big")


def even_y_from_x(x: int) -> int:
    curve = CURVES[CURVE_ID.value]
    y = pow((pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p, (curve.p + 1) // 4, curve.p)
    if y & 1:
        y = curve.p - y
    assert (y * y - (pow(x, 3, curve.p) + curve.a * x + curve.b)) % curve.p == 0
    return y


def serialize_signature(job: dict, allow_invalid: bool = False) -> list[int]:
    signature = bytes.fromhex(job["signature"])
    if len(signature) != 64:
        raise ValueError(f"{job['role']}: signature must be exactly 64 bytes")
    px = int(job["public_key"], 16)
    py = even_y_from_x(px)
    rx = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    message_hash = int(job["message_hash"], 16)
    curve = CURVES[CURVE_ID.value]
    e = tagged_challenge(rx, px, message_hash) % curve.n

    public_key = G1Point(px, py, CURVE_ID)
    result = G1Point.get_nG(CURVE_ID, 1).scalar_mul(s).add(
        public_key.scalar_mul((-e) % curve.n)
    )
    if not allow_invalid and (result.x != rx or result.y & 1):
        raise ValueError(f"{job['role']}: BIP340 signature is invalid for the supplied digest")

    serialized: list[int] = []
    serialized.extend(bigint_split(rx, N_LIMBS, BASE))
    serialized.extend(split_128(s))
    serialized.extend(split_128(e))
    serialized.extend(bigint_split(px, N_LIMBS, BASE))
    serialized.extend(bigint_split(py, N_LIMBS, BASE))
    serialized.extend(
        MSMCalldataBuilder(
            curve_id=CURVE_ID,
            points=[G1Point.get_nG(CURVE_ID, 1), public_key],
            scalars=[s, (-e) % curve.n],
        ).serialize_to_calldata(
            include_points_and_scalars=False,
            serialize_as_pure_felt252_array=True,
            use_rust=False,
        )
    )
    return serialized


def main() -> None:
    if len(sys.argv) not in (3, 4):
        raise SystemExit(
            "usage: generate-garaga-arguments.py INPUT.witness-input.json OUTPUT.arguments.json "
            "[--test-only-allow-invalid]"
        )
    allow_invalid = len(sys.argv) == 4 and sys.argv[3] == "--test-only-allow-invalid"
    if len(sys.argv) == 4 and not allow_invalid:
        raise ValueError("unknown fourth argument")
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    metadata = json.loads(source.read_text(encoding="utf-8"))
    if metadata["schema"] != "BarkShinigamiGaragaWitnessInputV1":
        raise ValueError("unsupported witness-input schema")
    if metadata["garaga_commit"] != GARAGA_COMMIT:
        raise ValueError("Garaga commit mismatch")

    jobs = metadata["signature_jobs"]
    arguments = list(metadata["byte_array_arguments"])
    arguments.append(hex(len(jobs)))
    for job in jobs:
        arguments.extend(hex(value) for value in serialize_signature(job, allow_invalid))
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(arguments, indent=2) + "\n", encoding="utf-8")
    print(f"path={destination}")
    print(f"signatures={len(jobs)}")
    print(f"felt_arguments={len(arguments)}")
    print(f"test_only_allow_invalid={str(allow_invalid).lower()}")


if __name__ == "__main__":
    main()
