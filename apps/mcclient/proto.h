#pragma once

#include <cstdint>

/* MAGIC */
#define MC_MAGIC_REQUEST 0x80
#define MC_MAGIC_RESPONSE 0x81

/* OPCODE */
#define MC_OP_GET 0x00
#define MC_OP_SET 0x01
#define MC_OP_ADD 0x02
#define MC_OP_REPLACE 0x03
#define MC_OP_DELETE 0x04
#define MC_OP_INC 0x05
#define MC_OP_DEC 0x06
#define MC_OP_QUIT 0x07
#define MC_OP_FLUSH 0x08
#define MC_OP_GETQ 0x09
#define MC_OP_NOOP 0x0a
#define MC_OP_VER 0x0b
#define MC_OP_GETK 0x0c
#define MC_OP_GETKQ 0x0d
#define MC_OP_APPEND 0x0e
#define MC_OP_PREPEND 0x0f
#define MC_OP_STATS 0x11

/* RESPONSE STATUS */
#define MC_RES_NO_ERR 0x0000
#define MC_RES_KEY_NOT_FOUND 0x0001
#define MC_RES_KEY_EXIST 0x0002
#define MC_RES_VALUE_TOO_LARGE 0x0003
#define MC_RES_INVALID_ARG 0x0004
#define MC_RES_ITEM_NOT_STORED 0x0005
#define MC_RES_INC_DEC_NON_NUMERIC 0x0006
#define MC_RES_VBUCKET_INVALID 0x0007
#define MC_RES_AUTH_ERR 0x0008
#define MC_RES_AUTH_CONT 0x0009
#define MC_RES_UNKNOWN_COMM 0x0081
#define MC_RES_OOM 0x0082
#define MC_RES_NOT_SUPPORTED 0x0083
#define MC_RES_INTER_ERR 0x0084
#define MC_RES_BUSY 0x0085
#define MC_RES_TEMP_FAIL 0x0086

struct MemcachedHdr {
  uint8_t magic;
  uint8_t opcode;
  uint16_t key_length;
  uint8_t extra_length;
  uint8_t data_type;
  uint16_t reserved_or_status;
  uint32_t total_body_length;
  uint32_t opaque;
  uint64_t cas;
} __packed;
static_assert(sizeof(MemcachedHdr) == 24);

static uint64_t mc_swap64(uint64_t in) {
    /* Little endian, flip the bytes around until someone makes a faster/better
    * way to do this. */
    int64_t rv = 0;
    int i = 0;
     for(i = 0; i<8; i++) {
        rv = (rv << 8) | (in & 0xff);
        in >>= 8;
     }
    return rv;
}

uint64_t ntohll(uint64_t val) {
   return mc_swap64(val);
}

uint64_t htonll(uint64_t val) {
   return mc_swap64(val);
}

void hton(struct MemcachedHdr *hdr) {
  hdr->key_length = htons(hdr->key_length);
  hdr->reserved_or_status = htons(hdr->reserved_or_status);
  hdr->total_body_length = htonl(hdr->total_body_length);
  hdr->opaque = htonl(hdr->opaque);
  hdr->cas = htonll(hdr->cas);
}

void ntoh(struct MemcachedHdr *hdr) {
  hdr->key_length = ntohs(hdr->key_length);
  hdr->reserved_or_status = ntohs(hdr->reserved_or_status);
  hdr->total_body_length = ntohl(hdr->total_body_length);
  hdr->opaque = ntohl(hdr->opaque);
  hdr->cas = ntohll(hdr->cas);
}

ssize_t ConstructMemcachedSetReq(
    char* _buf, int _buflen, uint32_t _id, const char *_key, uint16_t _key_len,
    const char *_value, uint32_t _value_len) {
  char *buf = _buf;
  struct MemcachedHdr *hdr;
  uint32_t body_len = 8 + _key_len + _value_len;

  if ((unsigned int)_buflen < sizeof(struct MemcachedHdr) + body_len)
    return 0;

  /* header */
  hdr = reinterpret_cast<struct MemcachedHdr *>(_buf);
  hdr->magic = MC_MAGIC_REQUEST;
  hdr->opcode = MC_OP_SET;
  hdr->key_length = _key_len;
  hdr->extra_length = 8;
  hdr->data_type = 0;
  hdr->reserved_or_status = 0;
  hdr->total_body_length = body_len;
  hdr->opaque = _id;
  hdr->cas = 0;
  buf += sizeof(struct MemcachedHdr);

  /* extra field: Flag (4), Expiration (4) */
  memset(buf, 0x00, 8);
  buf += 8;

  /* key */
  memcpy(buf, _key, _key_len);
  buf += _key_len;

  /* value */
  memcpy(buf, _value, _value_len);
  buf += _value_len;

  return (buf - _buf);
}

ssize_t ConstructMemcachedGetReq(
    char* _buf, int _buflen, uint32_t _id, const char *_key, uint16_t _key_len) {
  char *buf = _buf;
  struct MemcachedHdr *hdr;
  uint32_t body_len = _key_len;

  if ((unsigned int)_buflen < sizeof(struct MemcachedHdr) + body_len)
    return 0;

  /* header */
  hdr = reinterpret_cast<struct MemcachedHdr *>(_buf);
  hdr->magic = MC_MAGIC_REQUEST;
  hdr->opcode = MC_OP_GET;
  hdr->key_length = _key_len;
  hdr->extra_length = 0;
  hdr->data_type = 0;
  hdr->reserved_or_status = 0;
  hdr->total_body_length = body_len;
  hdr->opaque = _id;
  hdr->cas = 0;
  buf += sizeof(struct MemcachedHdr);

  /* key */
  memcpy(buf, _key, _key_len);
  buf += _key_len;

  return (buf - _buf);
}
