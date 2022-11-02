#pragma once

#define LDB_CANARY 0xDEADBEEF

static inline void __ldb_add_tag(uint32_t tag_) {
  uint64_t tag = ((uint64_t)LDB_CANARY) << 32 | tag_;
  __asm volatile ("movq %0, %%fs:-24 \n\t" :: "r"(tag) : "memory");
}

static inline void __ldb_clear_tag() {
  uint64_t tag = ((uint64_t)LDB_CANARY) << 32;
  __asm volatile ("movq %0, %%fs:-24 \n\t" :: "r"(tag): "memory");
}

static inline uint32_t __ldb_get_tag() {
  uint64_t tag;

  __asm volatile ("movq %%fs:-24, %0 \n\t" : "=r"(tag) :: "memory");

  return (uint32_t)(tag & 0xffffffff);
}
