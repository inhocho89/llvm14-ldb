#pragma once

static inline void __ldb_add_tag(uint64_t tag) {
  asm volatile ("movq %0, %%fs:-24 \n\t" :: "r"(tag) : "memory");
}

static inline void __ldb_clear_tag() {
  asm volatile ("movq $0, %%fs:-24 \n\t" ::: "memory");
}

inline uint64_t __ldb_get_tag() {
  uint64_t tag;

  asm volatile ("movq %%fs:-24, %0 \n\t" : "=r"(tag) :: "memory");

  return tag;
}
