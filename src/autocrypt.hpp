#pragma once

#ifndef _WIN32
#error autocrypt created only for windows x86\x64 platforms
#endif

#include <windows.h>
#include <array>
#include <type_traits>
#include <utility>

namespace autocrypt_core::crypto {
    inline constexpr std::size_t kStateCount = 16;
     inline constexpr std::size_t kAlphabetSize = 256;
    inline constexpr std::size_t kLayerCount = 2;

    struct DfaStateMatrix {
        std::array<std::array<std::array<std::uint8_t, kAlphabetSize>, kStateCount>, kLayerCount> table{};
        std::array<std::array<std::uint8_t, kStateCount>, kLayerCount> output{};
        std::array<std::uint8_t, kLayerCount> initial{};
    };

    template<typename CharT, std::size_t N>
    struct FixedString {
        CharT buffer[N];
        constexpr std::size_t Size() const noexcept { return N - 1; }
    };

    template<typename CharT, std::size_t N>
    FixedString(const CharT(&)[N]) -> FixedString<CharT, N>;

    template<typename CharT, std::size_t Size>
    struct CryptBuffer {
        std::array<std::uint8_t, Size * sizeof(CharT)> data{};
    };

    namespace detail {
        inline constexpr std::uint64_t kFnvBasis = 0xcbf29ce484222325;
        inline constexpr std::uint64_t kFnvPrime = 0x100000001b3;

        constexpr std::uint64_t Hash64(const char* data, const std::size_t size) noexcept {
            std::uint64_t hash = kFnvBasis;
            for (std::size_t i = 0; i < size; ++i) {
                hash ^= static_cast<std::uint8_t>(data[i]);
                hash *= kFnvPrime;
            }
            return hash;
        }

        constexpr std::uint8_t RotL8(const std::uint8_t value, const std::uint32_t shift) noexcept {
            return static_cast<std::uint8_t>((value << (shift & 7)) | (value >> (8 - (shift & 7))));
        }

        constexpr std::uint8_t ScrambleByte(std::uint8_t value) noexcept {
            value ^= 0xA5; value = RotL8(value, 3); value ^= 0x5A;
            value = static_cast<std::uint8_t>(value * 0x2D); value ^= (value >> 4);
            value = RotL8(value, 5); value ^= 0xC3;
            return value;
        }

        constexpr std::uint8_t PermuteByte(std::uint8_t value) noexcept {
            value = static_cast<std::uint8_t>(value * 0x67); value ^= 0x3C;
            value = static_cast<std::uint8_t>(((value & 0x0F) << 4) | ((value & 0xF0) >> 4));
            value ^= 0xB4; value = static_cast<std::uint8_t>(value * 0x9D);
            value ^= (value >> 3);
            return value;
        }
    }

    template<std::uint32_t Seed>
    constexpr auto BuildMatrix() noexcept {
        DfaStateMatrix dfa{};
        std::uint32_t key = Seed ^ 0x55555555;
        for (std::size_t layer = 0; layer < kLayerCount; ++layer) {
            key = (key << 7) | (key >> 25); key ^= 0xA5A5A5A5;
            dfa.initial[layer] = static_cast<std::uint8_t>(key % kStateCount);
            for (std::size_t state = 0; state < kStateCount; ++state) {
                dfa.output[layer][state] = detail::ScrambleByte(static_cast<std::uint8_t>(state ^ (key >> 8)));
                for (std::size_t symbol = 0; symbol < kAlphabetSize; ++symbol) {
                    dfa.table[layer][state][symbol] = detail::PermuteByte(static_cast<std::uint8_t>(state ^ symbol ^ (key & 0xFF))) % kStateCount;
                }
            }
        }
        return dfa;
    }

    template<FixedString ObjStr, std::uint32_t Seed>
    consteval auto Transform() noexcept {
        using CharType = std::remove_cvref_t<decltype(ObjStr.buffer[0])>;
        constexpr std::size_t char_count = ObjStr.Size();
        constexpr auto dfa = BuildMatrix<Seed>();
        CryptBuffer<CharType, char_count> encrypted{};
        std::array<std::uint8_t, kLayerCount> states = dfa.initial;

        for (std::size_t i = 0; i < char_count; ++i) {
            const auto raw_char = static_cast<std::uint16_t>(ObjStr.buffer[i]);
            const std::size_t byte_idx = i * sizeof(CharType);
            for (std::size_t offset = 0; offset < sizeof(CharType); ++offset) {
                auto symbol = static_cast<std::uint8_t>((raw_char >> (offset * 8)) & 0xFF);
                for (std::size_t layer = 0; layer < kLayerCount; ++layer) {
                    const std::uint8_t current_state = states[layer];
                    symbol ^= dfa.output[layer][current_state] ^ detail::ScrambleByte(static_cast<std::uint8_t>((byte_idx + offset) ^ layer));
                    states[layer] = dfa.table[layer][current_state][symbol];
                }
                encrypted.data[byte_idx + offset] = symbol;
            }
        }
        return std::make_pair(dfa, encrypted);
    }

    template<FixedString ObjStr, std::uint32_t Seed>
    struct InjectedData {
        static constexpr auto value = Transform<ObjStr, Seed>();
    };

    template<FixedString ObjStr, std::uint32_t Seed>
    class StackDecrypter {
    public:
        using CharT = std::remove_cvref_t<decltype(ObjStr.buffer[0])>;
        static constexpr std::size_t CharCount = ObjStr.Size();

        __forceinline StackDecrypter() noexcept {
            constexpr auto dfa = InjectedData<ObjStr, Seed>::value.first;
            constexpr auto encrypted = InjectedData<ObjStr, Seed>::value.second;
            std::array<std::uint8_t, kLayerCount> states = dfa.initial;
            volatile std::uintptr_t stack_ctx = reinterpret_cast<std::uintptr_t>(&states);

            for (std::size_t i = 0; i < CharCount; ++i) {
                const std::size_t byte_idx = i * sizeof(CharT);
                std::uint16_t accumulator = 0;

                for (std::size_t offset = 0; offset < sizeof(CharT); ++offset) {
                    std::uint8_t symbol = encrypted.data[byte_idx + offset];
                    volatile std::uint32_t FsmState = (stack_ctx != 0) ? 0x100 : 0x0;

                    while (FsmState != 0x300) {
                        switch (FsmState) {
                        case 0x100:
                            for (int layer = static_cast<int>(kLayerCount) - 1; layer >= 0; --layer) {
                                const std::uint8_t current_state = states[layer];
                                const std::uint8_t cipher_byte = symbol;
                                symbol ^= dfa.output[layer][current_state] ^ detail::ScrambleByte(static_cast<std::uint8_t>((byte_idx + offset) ^ layer));
                                states[layer] = dfa.table[layer][current_state][cipher_byte];
                            }
                            FsmState = 0x200 + (stack_ctx & 0x0);
                            break;
                        case 0x200: FsmState = 0x300; break;
                        default: FsmState = 0x300; break;
                        }
                    }
                    accumulator |= static_cast<std::uint16_t>(symbol) << (offset * 8);
                }
                storage[i] = static_cast<CharT>(accumulator);
            }
            storage[CharCount] = static_cast<CharT>(0);
        }

        StackDecrypter(const StackDecrypter&) = delete;
        StackDecrypter& operator=(const StackDecrypter&) = delete;
        __forceinline StackDecrypter(StackDecrypter&& other) noexcept : storage(std::move(other.storage)) {
            other.storage.fill(static_cast<CharT>(0));
        }

        __forceinline ~StackDecrypter() noexcept {
            volatile CharT* p = reinterpret_cast<volatile CharT*>(storage.data());
            for (std::size_t i = 0; i <= CharCount; ++i) { p[i] = static_cast<CharT>(0); }
        }

        [[nodiscard]] __forceinline operator const CharT*() const noexcept { return storage.data(); }
        [[nodiscard]] __forceinline const CharT* Get() const noexcept { return storage.data(); }

    private:
        std::array<CharT, CharCount + 1> storage;
    };
}

#define AUTOSTR(str) autocrypt_core::crypto::StackDecrypter<autocrypt_core::crypto::FixedString(str), static_cast<std::uint32_t>(autocrypt_core::crypto::detail::Hash64(__TIMESTAMP__, sizeof(__TIMESTAMP__)) ^ __COUNTER__)>()
