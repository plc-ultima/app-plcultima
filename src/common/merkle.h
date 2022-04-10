
#pragma once

#include <stdint.h>

// TODO: RFC6962 defines the empty list hash as sha256(b''); while we're using 0 here. Should we
// change?

/*
  Implementation of Merkle proof verification. Follows RFC 6962:
  https://www.rfc-editor.org/rfc/pdfrfc/rfc6962.txt.pdf, using SHA256 as the hash function.

  Namely (||| denodes concatenation):
  - leaf hashes for an element x are computed as SHA256(0x00 ||| x)
  - internal element hashes for a note with left child hashing to l_hash and right child hashing to
  r_hash is: SHA256(0x01 ||| l_hash ||| r_hash)

  This ensures that no two trees with the same root hash can be computed.

  This implementation has 128 bits of collision-resistance security if the attacker can choose the
  value of leaves. If the attacker cannot control inserted leaves, then finding a collision is as
  hard as chosen-preimage for SHA256.
*/

/**
 * The maximum depth supported for the Merkle tree, where the root has depth 0.
 * The maximum number of elements supported is therefore pow(2, MAX_MERKLE_TREE_DEPTH).
 */
#define MAX_MERKLE_TREE_DEPTH 32

/**
 * Convenience method to compute the hash of an element for the Merkle tree, which is the SHA256
 * hash of the input buffer, prepended with a 0x00 byte.
 *
 * @param[in] in
 *   Pointer to the input buffer.
 * @param[in] in_len
 *   Length of the input buffer.
 * @param[out] out
 *   Pointer to a 32-bytes buffer to store the result.
 */
void merkle_compute_element_hash(const uint8_t *in, size_t in_len, uint8_t out[static 32]);

/**
 * Computes the hash for an internal node of the Merkle tree, given the hashes of its children.
 * The result is the output of SHA256 on the concatenation of the byte 0x01, the left child hash,
 * and the right child hash.
 *
 * @param[in] left
 *   Pointer to the input buffer.
 * @param[in] right
 *   Length of the input buffer.
 * @param[out] out
 *   Pointer to a 32-bytes buffer to store the result.
 */
void merkle_combine_hashes(const uint8_t left[static 32],
                           const uint8_t right[static 32],
                           uint8_t out[static 32]);

// inlined to save on stack depth
static inline uint8_t ceil_lg(uint32_t n) {
    uint8_t r = 0;
    uint32_t t = 1;
    while (t < n) {
        t = 2 * t;
        ++r;
    }
    return r;
}

// Returns the ith member of the directions array for the leaf with the given index in a Merkle tree
// of the given size. Returns -1 on error.
// TODO: make this O(log n), or possibly O(1). Currently O(log^2 n).
//
// inlined to save on stack depth (only used once anyway, so no impact on code size)
static inline int merkle_get_ith_direction(size_t size, size_t index, size_t i) {
    if (size <= 1 || index >= size) {
        return -1;
    }

    uint8_t n_directions = 0;
    while (size > 1) {
        uint8_t depth = ceil_lg(size);

        // bitmask of the direction from the current node, where 0 = left, 1 = right;
        // also the number of leaves of the left subtree
        uint32_t mask = 1 << (depth - 1);

        uint8_t is_right_child = (index & mask) != 0 ? 1 : 0;

        if (n_directions == i) {
            return is_right_child;
        }

        ++n_directions;

        if (is_right_child) {
            size -= mask;
            index -= mask;
        } else {
            size = mask;
        }

        mask /= 2;
    }

    return -1;
}

/**
 * Represents the Merkleized version of a key-value map, holding the number of elements, the root of
 * the Merkle tree of the sorted list of keys, and the root of the Merkle tree of the values (sorted
 * by their correpsonding key).
 */
typedef struct {
    uint64_t size;
    uint8_t keys_root[32];
    uint8_t values_root[32];
} merkleized_map_commitment_t;