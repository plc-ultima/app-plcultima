#include <string.h>

#include "check_merkle_tree_sorted.h"
#include "get_merkle_leaf_element.h"

static int compare_byte_arrays(const uint8_t array1[],
                               size_t array1_len,
                               const uint8_t array2[],
                               size_t array2_len);

int call_check_merkle_tree_sorted_with_callback(dispatcher_context_t *dispatcher_context,
                                                const uint8_t root[static 32],
                                                size_t size,
                                                dispatcher_callback_descriptor_t callback) {
    // LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    int prev_el_len = 0;
    uint8_t prev_el[MAX_CHECK_MERKLE_TREE_SORTED_PREIMAGE_SIZE];

    for (size_t cur_el_idx = 0; cur_el_idx < size; cur_el_idx++) {
        uint8_t cur_el[MAX_CHECK_MERKLE_TREE_SORTED_PREIMAGE_SIZE];
        int cur_el_len = call_get_merkle_leaf_element(dispatcher_context,
                                                      root,
                                                      size,
                                                      cur_el_idx,
                                                      cur_el,
                                                      sizeof(cur_el));

        if (cur_el_len < 0) {
            return -1;
        }

        if (cur_el_idx > 0 && compare_byte_arrays(prev_el, prev_el_len, cur_el, cur_el_len) >= 0) {
            // elements are not in (strict) lexicographical order
            PRINTF("Keys not in order\n");
            return -1;
        }

        memcpy(prev_el, cur_el, cur_el_len);
        prev_el_len = cur_el_len;

        if (callback.fn != NULL) {
            // call callback with data
            buffer_t buf = buffer_create(cur_el, cur_el_len);
            callback.fn(callback.state, &buf);
        }
    }
    return 0;
}

// Returns a negative number, 0 or a positive number if the first array is (respectively)
// lexicographically smaller, equal, or larger than the second. If one array is prefix than the
// other, then the shorter ones comes first in lexicographical order.
// TODO: move this to a common utility file, and add tests
static int compare_byte_arrays(const uint8_t array1[],
                               size_t array1_len,
                               const uint8_t array2[],
                               size_t array2_len) {
    size_t min_len = array1_len < array2_len ? array1_len : array2_len;

    // it is unclear from the docs if memcmp(_, _, 0) is guaranteed to return 0; therefore we avoid
    // relying on it here.
    int memcmp_result;
    if (min_len == 0 || ((memcmp_result = memcmp(array1, array2, min_len)) == 0)) {
        // One of the arrays is a prefix of the other; the shortest comes first
        if (array1_len < array2_len)
            return -1;
        else if (array1_len > array2_len)
            return 1;
        else
            return 0;
    }

    return memcmp_result;
}