#pragma once
#include <cstdint>

#define DEBUG_MODE
#define VM_BLOB_CODE_SECTION ".vmb$code"

constexpr uint64_t get_seed() {
	uint64_t seed = 0;
	for (const char* c = __TIME__; *c; c++) {
		seed = (seed << 8) + *c;
	}

	return seed;
}

constexpr uint64_t get_random(uint64_t n) {
	return (get_seed() + n * 6364136223846793005ULL) + 1442695040888963407ULL;
}

template <int N>
struct generator {
#ifdef DEBUG_MODE
    __forceinline __declspec(code_seg(VM_BLOB_CODE_SECTION)) static void generate_junk() { return; }
#else
	__forceinline __declspec(code_seg(VM_BLOB_CODE_SECTION)) static void generate_junk() {
		constexpr int branch = get_random(N) % 6;

        // you can add as many branches as you want with garbage
		if constexpr (branch == 0) {
			volatile int counter = 0;
			constexpr int loop_limit = get_random(N) % 50;

			for (int i = 0; i < loop_limit; i++) {
				counter += i;
			}
		}
		else if constexpr (branch == 1) {
            volatile int fibonacci[6] = { 1, 1, 2, 3, 5, 8 };
            constexpr int idx = get_random(N + 5) % 6;
            fibonacci[idx] ^= idx * 31;
		}
		else if constexpr (branch == 2) {
			volatile char buffer[16];
            constexpr char value = static_cast<char>(get_random(N + 2) % 256);
			buffer[0] = value;
		} 
        else if constexpr (branch == 3) {
            constexpr uint32_t value = static_cast<uint32_t>(get_random(N + 6));
            volatile uint32_t x = value;
            x = (x << 7) | (x >> 25);
            x ^= 0x9E3779B9u;
        }
        else if constexpr (branch == 4) {
            constexpr int value = static_cast<int>(get_random(N + 7));
            volatile int x = value;
            volatile int y = x;

            y ^= 0xABCD;
            y ^= 0xABCD; // y == x again
            y += 13;
            y -= 13;
        } else if constexpr (branch == 5) {
            constexpr uint32_t value = static_cast<uint32_t>(get_random(N + 11));

            constexpr auto u32 = [](uint64_t x) constexpr -> uint32_t {
                return static_cast<uint32_t>(x & 0xFFFFFFFFULL);
            };

            constexpr auto rotl = [](uint32_t x, uint32_t r) constexpr -> uint32_t {
                r &= 31u;
                return static_cast<uint32_t>((x << r) | (x >> ((32u - r) & 31u)));
            };

            constexpr auto rotr = [](uint32_t x, uint32_t r) constexpr -> uint32_t {
                r &= 31u;
                return static_cast<uint32_t>((x >> r) | (x << ((32u - r) & 31u)));
            };

            constexpr auto mix = [](uint32_t x) constexpr -> uint32_t {
                x ^= x >> 16;
                x *= 0x7FEB352Du;
                x ^= x >> 15;
                x *= 0x846CA68Bu;
                x ^= x >> 16;
                return x;
            };

            constexpr auto parity_fold = [](uint32_t x) constexpr -> uint32_t {
                x ^= x >> 16;
                x ^= x >> 8;
                x ^= x >> 4;
                x ^= x >> 2;
                x ^= x >> 1;
                return x & 1u;
            };

            constexpr auto byte_swap = [](uint32_t x) constexpr -> uint32_t {
                return
                    ((x & 0x000000FFu) << 24) |
                    ((x & 0x0000FF00u) << 8)  |
                    ((x & 0x00FF0000u) >> 8)  |
                    ((x & 0xFF000000u) >> 24);
            };

            constexpr uint32_t a0 = mix(value ^ 0x9E3779B9u);
            constexpr uint32_t a1 = mix(a0 + 0x85EBCA6Bu);
            constexpr uint32_t a2 = mix(a1 ^ 0xC2B2AE35u);
            constexpr uint32_t a3 = mix(a2 + value + 0x27D4EB2Fu);

            constexpr uint32_t b0 = rotl(a0 ^ a2, 3);
            constexpr uint32_t b1 = rotr(a1 + a3, 7);
            constexpr uint32_t b2 = rotl(b0 ^ b1 ^ value, 13);
            constexpr uint32_t b3 = rotr(b2 + 0xA5A5A5A5u, 19);

            constexpr uint32_t c0 = byte_swap(byte_swap(a0));
            constexpr uint32_t c1 = byte_swap(byte_swap(a1));
            constexpr uint32_t c2 = byte_swap(byte_swap(a2));
            constexpr uint32_t c3 = byte_swap(byte_swap(a3));

            constexpr uint32_t d0 = rotl(rotr(b0, 3), 3);
            constexpr uint32_t d1 = rotr(rotl(b1, 7), 7);
            constexpr uint32_t d2 = rotl(rotr(b2, 13), 13);
            constexpr uint32_t d3 = rotr(rotl(b3, 19), 19);

            constexpr bool p_add_0 =
                static_cast<uint32_t>((a0 ^ a1) + ((a0 & a1) << 1)) ==
                static_cast<uint32_t>(a0 + a1);

            constexpr bool p_add_1 =
                static_cast<uint32_t>((a2 ^ a3) + ((a2 & a3) << 1)) ==
                static_cast<uint32_t>(a2 + a3);

            constexpr bool p_orand_0 =
                static_cast<uint32_t>((a0 | a1) + (a0 & a1)) ==
                static_cast<uint32_t>(a0 + a1);

            constexpr bool p_orand_1 =
                static_cast<uint32_t>((b2 | b3) + (b2 & b3)) ==
                static_cast<uint32_t>(b2 + b3);

            constexpr bool p_xor_cancel =
                (((a0 ^ 0xDEADBEEFu) ^ 0xDEADBEEFu) == a0) &&
                (((a1 ^ a2) ^ a2) == a1) &&
                (((a2 ^ a3) ^ a3) == a2) &&
                (((a3 ^ value) ^ value) == a3);

            constexpr bool p_rot_restore =
                c0 == a0 &&
                c1 == a1 &&
                c2 == a2 &&
                c3 == a3 &&
                d0 == b0 &&
                d1 == b1 &&
                d2 == b2 &&
                d3 == b3;

            constexpr bool p_even_products =
                (((static_cast<int>(value) * static_cast<int>(value)) - static_cast<int>(value)) % 2 == 0) &&
                (((static_cast<int>(value + 1) * static_cast<int>(value + 1)) - static_cast<int>(value + 1)) % 2 == 0) &&
                (((static_cast<int>(value + 2) * static_cast<int>(value + 2)) - static_cast<int>(value + 2)) % 2 == 0) &&
                (((static_cast<int>(value + 3) * static_cast<int>(value + 3)) - static_cast<int>(value + 3)) % 2 == 0);

            constexpr bool p_odd_square =
                ((((static_cast<int>(value) | 1) * (static_cast<int>(value) | 1)) & 7) == 1) &&
                ((((static_cast<int>(a0) | 1) * (static_cast<int>(a0) | 1)) & 7) == 1) &&
                ((((static_cast<int>(a1) | 1) * (static_cast<int>(a1) | 1)) & 7) == 1);

            constexpr bool p_mask_rebuild =
                (
                    ((a0 & 0xFF000000u) |
                    (a0 & 0x00FF0000u) |
                    (a0 & 0x0000FF00u) |
                    (a0 & 0x000000FFu)) == a0
                )
                &&
                (
                    ((a1 & 0xF0F0F0F0u) |
                    (a1 & 0x0F0F0F0Fu)) == a1
                )
                &&
                (
                    ((a2 & 0xAAAAAAAAu) |
                    (a2 & 0x55555555u)) == a2
                );

            constexpr bool p_split_xor =
                [](
                    uint32_t x,
                    uint32_t y
                ) constexpr -> bool {
                    uint32_t only_x = x & ~y;
                    uint32_t only_y = y & ~x;
                    uint32_t both   = x & y;

                    uint32_t rebuilt_or =
                        only_x |
                        only_y |
                        both;

                    uint32_t rebuilt_xor =
                        only_x |
                        only_y;

                    return
                        rebuilt_or == (x | y) &&
                        rebuilt_xor == (x ^ y) &&
                        ((rebuilt_xor | both) == (x | y)) &&
                        ((rebuilt_xor & both) == 0u);
                }(a0, a1);

            constexpr bool p_parity =
                [](
                    uint32_t x,
                    uint32_t y,
                    uint32_t z
                ) constexpr -> bool {
                    uint32_t px = parity_fold(x);
                    uint32_t py = parity_fold(y);
                    uint32_t pz = parity_fold(z);

                    uint32_t combined_0 = parity_fold(x ^ y ^ z);
                    uint32_t combined_1 = px ^ py ^ pz;

                    return combined_0 == combined_1;
                }(a0, a1, a2);

            constexpr bool p_annihilate =
                [](
                    uint32_t w,
                    uint32_t x,
                    uint32_t y,
                    uint32_t z
                ) constexpr -> bool {
                    uint32_t acc = 0;

                    acc ^= w; acc ^= w;
                    acc ^= x; acc ^= x;
                    acc ^= y; acc ^= y;
                    acc ^= z; acc ^= z;

                    acc ^= w ^ x;
                    acc ^= x ^ w;

                    acc ^= y ^ z;
                    acc ^= z ^ y;

                    acc ^= w ^ x ^ y ^ z;
                    acc ^= z ^ y ^ x ^ w;

                    return acc == 0u;
                }(a0, a1, a2, a3);

            constexpr bool p_demorgan =
                [](
                    bool q0,
                    bool q1,
                    bool q2,
                    bool q3
                ) constexpr -> bool {
                    bool left =
                        !(q0 && q1 && q2 && q3);

                    bool right =
                        (!q0 || !q1 || !q2 || !q3);

                    return left == right;
                }(p_add_0, p_add_1, p_orand_0, p_orand_1);

            constexpr bool p_boolean_maze_0 =
                (
                    (p_add_0 && p_add_1 && p_orand_0) ||
                    (p_add_0 && p_add_1 && !p_orand_0 && p_orand_0) ||
                    (p_add_0 && !p_add_1 && p_add_1 && p_orand_0)
                )
                &&
                !(
                    (!p_add_0 || !p_add_1 || !p_orand_0) &&
                    (p_add_0 && p_add_1 && p_orand_0)
                );

            constexpr bool p_boolean_maze_1 =
                (
                    (p_xor_cancel ? p_rot_restore : false) &&
                    (p_even_products || (!p_even_products && p_even_products)) &&
                    ((p_odd_square && p_mask_rebuild) || false)
                );

            constexpr bool p_comparator_noise =
                [](
                    uint32_t x,
                    uint32_t y
                ) constexpr -> bool {
                    uint32_t min_xy = (x < y) ? x : y;
                    uint32_t max_xy = (x < y) ? y : x;

                    return
                        min_xy <= max_xy &&
                        !(max_xy < min_xy) &&
                        ((x == y) ? (min_xy == max_xy) : (min_xy != max_xy));
                }(b0, b1);

            constexpr bool p_arithmetic_loop =
                [](
                    uint32_t x
                ) constexpr -> bool {
                    uint32_t t = x;

                    for (int i = 0; i < 8; ++i) {
                        t += static_cast<uint32_t>(i * 17 + 3);
                        t -= static_cast<uint32_t>(i * 17 + 3);
                        t ^= static_cast<uint32_t>(0x11111111u * i);
                        t ^= static_cast<uint32_t>(0x11111111u * i);
                    }

                    return t == x;
                }(a3);

            constexpr bool p_table_noise =
                [](
                    uint32_t x,
                    uint32_t y,
                    uint32_t z
                ) constexpr -> bool {
                    uint32_t table[8] = {
                        x,
                        y,
                        z,
                        x ^ y,
                        y ^ z,
                        z ^ x,
                        x | y | z,
                        x & y & z
                    };

                    uint32_t acc = 0;

                    for (int i = 0; i < 8; ++i) {
                        acc ^= table[i];
                        acc ^= table[7 - i];
                    }

                    uint32_t mirror = 0;

                    for (int i = 7; i >= 0; --i) {
                        mirror ^= table[i];
                        mirror ^= table[7 - i];
                    }

                    return acc == 0u && mirror == 0u;
                }(a0, a1, a2);

            constexpr bool p_modular_noise =
                [](
                    uint32_t x
                ) constexpr -> bool {
                    uint32_t odd = x | 1u;

                    bool r0 = ((odd * odd) & 7u) == 1u;
                    bool r1 = (((odd + 2u) * (odd + 2u)) & 7u) == 1u;
                    bool r2 = (((odd + 4u) * (odd + 4u)) & 7u) == 1u;

                    return r0 && r1 && r2;
                }(value);

            constexpr bool p_bit_equivalence =
                [](
                    uint32_t x,
                    uint32_t y
                ) constexpr -> bool {
                    uint32_t lhs0 = ~(x & y);
                    uint32_t rhs0 = (~x) | (~y);

                    uint32_t lhs1 = ~(x | y);
                    uint32_t rhs1 = (~x) & (~y);

                    return lhs0 == rhs0 && lhs1 == rhs1;
                }(b2, b3);

            constexpr bool p_nested_choice =
                ((a0 & 1u)
                    ? ((a1 & 2u)
                        ? (p_add_0 && p_xor_cancel)
                        : (p_xor_cancel && p_add_0))
                    : ((a2 & 4u)
                        ? (p_add_0 || false)
                        : (!false && p_add_0)));

            constexpr bool p_nested_choice_2 =
                ((b0 & 8u)
                    ? ((b1 & 16u)
                        ? ((p_mask_rebuild && p_split_xor) || false)
                        : ((p_split_xor && p_mask_rebuild) && true))
                    : ((b2 & 32u)
                        ? (!(!p_mask_rebuild) && p_split_xor)
                        : (p_split_xor ? p_mask_rebuild : false)));

            constexpr bool opaque =
                (
                    p_add_0 &&
                    p_add_1 &&
                    p_orand_0 &&
                    p_orand_1 &&
                    p_xor_cancel &&
                    p_rot_restore &&
                    p_even_products &&
                    p_odd_square
                )
                &&
                (
                    p_mask_rebuild &&
                    p_split_xor &&
                    p_parity &&
                    p_annihilate &&
                    p_demorgan &&
                    p_boolean_maze_0 &&
                    p_boolean_maze_1
                )
                &&
                (
                    p_comparator_noise &&
                    p_arithmetic_loop &&
                    p_table_noise &&
                    p_modular_noise &&
                    p_bit_equivalence &&
                    p_nested_choice &&
                    p_nested_choice_2
                )
                &&
                !(
                    (!p_add_0 || !p_add_1) ||
                    (!p_orand_0 && p_orand_0) ||
                    (p_xor_cancel && !p_xor_cancel) ||
                    !(p_rot_restore && p_even_products && p_odd_square) ||
                    !(p_mask_rebuild && p_split_xor && p_parity) ||
                    !(p_annihilate && p_demorgan) ||
                    !(p_boolean_maze_0 && p_boolean_maze_1) ||
                    !(p_comparator_noise && p_arithmetic_loop) ||
                    !(p_table_noise && p_modular_noise && p_bit_equivalence)
                );

            if constexpr (opaque) {
                volatile uint32_t x = value;
                volatile uint32_t y = a0;
                volatile uint32_t z = a1;
                volatile uint32_t w = a2;

                x ^= 0xA5A5A5A5u;
                x ^= 0xA5A5A5A5u;

                y += 0x13371337u;
                y -= 0x13371337u;

                z = (z << 3) | (z >> 29);
                z ^= 0x9E3779B9u;
                z ^= 0x9E3779B9u;
                z = (z >> 3) | (z << 29);

                w += x;
                w -= x;
                w ^= y;
                w ^= y;

                volatile uint32_t sink0 =
                    static_cast<uint32_t>((x ^ y) + ((x & y) << 1));

                volatile uint32_t sink1 =
                    static_cast<uint32_t>((z | w) + (z & w));

                volatile uint32_t sink2 =
                    static_cast<uint32_t>(
                        rotl(static_cast<uint32_t>(sink0 ^ sink1), 11) ^
                        rotr(static_cast<uint32_t>(sink0 + sink1), 5)
                    );

                sink0 ^= static_cast<uint32_t>(N);
                sink1 += sink0;
                sink2 ^= sink1;

                volatile uint32_t garbage[8] = {
                    sink0,
                    sink1,
                    sink2,
                    x,
                    y,
                    z,
                    w,
                    static_cast<uint32_t>(N)
                };

                for (int i = 0; i < 8; ++i) {
                    garbage[i] ^= static_cast<uint32_t>(i * 0x45D9F3Bu);
                    garbage[i] += static_cast<uint32_t>((7 - i) * 0x27D4EB2Fu);
                    garbage[i] = static_cast<uint32_t>(
                        (garbage[i] << ((i + 3) & 31)) |
                        (garbage[i] >> ((32 - ((i + 3) & 31)) & 31))
                    );
                }
            } else {
                volatile uint32_t impossible = value;

                impossible ^= 0xDEADBEEFu;
                impossible += 0xCAFEBABEu;
                impossible = (impossible << 17) | (impossible >> 15);
                impossible ^= static_cast<uint32_t>(N * 0x9E3779B9u);
            }
        }

		generator<N - 1>::generate_junk();
	}
#endif
};


template <>
struct generator<0> {
	__forceinline __declspec(code_seg(VM_BLOB_CODE_SECTION)) static void generate_junk() {
		// base case: do nothing
	}
};
