#include "vault_drive.h"
#include "vault_storage.h"
#include "vault_crypto.h"
#include "esp_vfs_fat.h"
#include "esp_log.h"
#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define ROOT VAULT_DIR "/usb-drive.hdr"
#define JOURNAL VAULT_DIR "/usb-drive.txn"
#define SEGMENT_BLOCKS 16384U
#define ROOT_BYTES 8192U
#define BLOCK_BYTES 4096U
#define SD_SECTOR 512U
/* Every SD transfer goes through one internal, DMA-capable staging buffer.
 * The ESP32-S3 SDMMC host cannot DMA to or from PSRAM: ESP-IDF splits any
 * PSRAM transfer into one 512-byte command per sector through a bounce buffer,
 * which made journal/segment writes and record reads several times slower.
 * The same buffer holds read-ahead ciphertext for sequential reads. */
#ifndef VAULT_DRIVE_STAGE_BYTES
#define VAULT_DRIVE_STAGE_BYTES (32U * 1024U)
#endif
#define MIN_STAGE_BYTES (8U * 1024U)
#ifdef VAULT_DRIVE_TEST
extern bool vault_drive_test_stop(unsigned stage);
static unsigned s_test_fetches; /* segment record reads, for read-ahead checks */
#else
#define vault_drive_test_stop(stage) false
#endif
#ifndef VAULT_DRIVE_MAX_SECTORS
#define VAULT_DRIVE_MAX_SECTORS 0xfffff800U
#endif
/* Dirty 4 KB blocks held in RAM (PSRAM) and committed together under one
 * batch journal; a flush writes at most this many data records. */
#ifndef VAULT_DRIVE_CACHE_BLOCKS
#define VAULT_DRIVE_CACHE_BLOCKS 128U
#endif
#define FALLBACK_CACHE_BLOCKS 4U
static const char *TAG = "vault_drive";
/* All persistent structures use the ESP32/little-endian layout, versioned by
 * their magic. Every block, allocation map and root is authenticated separately. */
typedef struct __attribute__((packed)) {
    uint32_t sectors, fat_sectors;
    uint8_t cluster_sectors, reserved[7], created[4096], padding[4080];
} root_plain_t;
typedef struct __attribute__((packed)) {
    uint8_t magic[8], uuid[16], iv[12], tag[16], ciphertext[ROOT_BYTES];
} root_record_t;
typedef struct __attribute__((packed)) {
    uint8_t iv[12], tag[16], ciphertext[BLOCK_BYTES];
} record_t;
typedef struct __attribute__((packed)) {
    uint8_t domain[8], uuid[16];uint32_t segment, block;
} aad_t;
typedef struct __attribute__((packed)) {
    uint8_t magic[8], uuid[16];uint32_t segment, block, new_segment;
    uint8_t iv[12], tag[16];
} journal_header_t;
/* Batch journal (VLTTXN3): prefix, iv, tag, entry table, one record per
 * entry, then the root record. The tag authenticates the prefix and table;
 * each record is authenticated by its own segment/block AAD. Entries are
 * grouped by ascending segment: a map entry (block UINT32_MAX) followed by
 * that segment's data entries in ascending block order. */
typedef struct __attribute__((packed)) {
    uint8_t magic[8], uuid[16];uint32_t count, reserved;
} batch_prefix_t;
typedef struct __attribute__((packed)) {
    uint32_t segment, block, new_segment;
} entry_t;
_Static_assert(sizeof(root_plain_t)==ROOT_BYTES,"Root layout changed");
/* Within a segment file, record position 0 is the allocation map and data
 * block b is at position b+1. Every on-card offset is a multiple of 4 bytes. */
_Static_assert(sizeof(record_t)%4==0 && sizeof(root_record_t)%4==0,"Record alignment changed");
static struct {
    root_plain_t root;
    root_record_t root_record;
    record_t data_record, map_record; /* legacy VLTTXN2 journal replay */
    uint8_t map[BLOCK_BYTES], plain[BLOCK_BYTES];
    uint32_t cap, dirty_count, read_segment, last_block;
    uint32_t *dirty_block;
    uint16_t *order;
    uint8_t *dirty_plain, *batch; /* batch: prefix followed by the entry table */
    record_t *records;
    int reader; /* read-only descriptor on read_segment, or -1 */
    uint8_t *stage;size_t stage_size;
    bool ra_valid, last_valid;
    uint32_t ra_segment, ra_first, ra_count; /* staged records by position */
    vault_gcm_t *gcm;
} *s;
static const char *s_last_error="none";
const char *vault_drive_last_error(void) { return s_last_error; }
static bool s_ready,s_creating,s_cached,s_map_cached,s_read_only;
static uint32_t s_cache_block,s_map_segment;
static bool bit(const uint8_t *p,uint32_t i) { return (p[i/8]>>(i%8))&1; }
static void setbit(uint8_t *p,uint32_t i) { p[i/8]|=1U<<(i%8); }
static void segment_path(char *out,size_t n,uint32_t seg) { snprintf(out,n,VAULT_DIR "/usb-%05lu.enc",(unsigned long)seg); }
static bool exists(const char *path) { struct stat st;return stat(path,&st)==0; }
bool vault_drive_exists(void) { return exists(ROOT)||exists(ROOT ".bak")||exists(JOURNAL); }
bool vault_drive_ready(void) { return s_ready; }
bool vault_drive_creating(void) { return s_creating; }
unsigned vault_drive_progress(void) { return s_ready?100:0; }
uint32_t vault_drive_sector_count(void) { return s && (s_ready||s_creating)?s->root.sectors:0; }
void vault_drive_set_read_only(bool read_only) { s_read_only=read_only; }
bool vault_drive_read_only(void) { return s_read_only; }
static void ra_drop(void) { s->ra_valid=false; }
static void close_reader(void) {
    if(s && s->reader>=0) { close(s->reader);s->reader=-1; }
    if(s) ra_drop();
}
static void release(void *p,size_t n) { if(p) { vault_secure_zero(p,n);free(p); } }
static size_t batch_bytes(uint32_t cap) { return sizeof(batch_prefix_t)+2*cap*sizeof(entry_t); }
/* Frees everything, discarding any unflushed blocks; used on failure paths. */
static void drop(void) {
    s_ready=s_creating=s_cached=s_map_cached=s_read_only=false;
    if(s) {
        close_reader();
        release(s->dirty_plain,(size_t)s->cap*BLOCK_BYTES);release(s->records,2*(size_t)s->cap*sizeof(record_t));
        release(s->batch,batch_bytes(s->cap));free(s->dirty_block);free(s->order);
        release(s->stage,s->stage_size);vault_gcm_destroy(s->gcm);
        vault_secure_zero(s,sizeof(*s));free(s);s=NULL;
    }
}
bool vault_drive_dirty(void) { return s && s->dirty_count; }

/* ---- SD I/O through the staging buffer ---- */
static bool io_full(int fd,void *buf,size_t n,bool write_op) {
    uint8_t *p=buf;
    while(n) {
        ssize_t r=write_op?write(fd,p,n):read(fd,p,n);
        if(r<=0)return false;
        p+=r;n-=(size_t)r;
    }
    return true;
}
static bool seek_to(int fd,uint64_t off) { return lseek(fd,(off_t)off,SEEK_SET)==(off_t)off; }
/* Copies a span at a file offset. Chunks after the first end on sector
 * boundaries, so FatFs moves whole sectors with multi-sector DMA commands
 * and only the span's first and last sectors are partial. */
static bool staged_io(int fd,uint64_t off,void *buf,size_t n,bool write_op) {
    ra_drop();
    if(!seek_to(fd,off))return false;
    uint8_t *p=buf;size_t chunk=s->stage_size-(size_t)(off%SD_SECTOR);
    while(n) {
        if(chunk>n)chunk=n;
        if(write_op)memcpy(s->stage,p,chunk);
        if(!io_full(fd,s->stage,chunk,write_op))return false;
        if(!write_op)memcpy(p,s->stage,chunk);
        p+=chunk;n-=chunk;chunk=s->stage_size;
    }
    return true;
}
static bool finish_fd(int fd,bool ok) {
    if(fsync(fd)!=0)ok=false;
    if(close(fd)!=0)ok=false;
    return ok;
}
/* Sequential whole-file writer (journal, root): full stage-sized chunks from
 * offset 0 are always sector aligned. */
typedef struct { int fd;size_t used;bool ok; } seq_t;
static bool seq_begin(seq_t *w,const char *path) {
    ra_drop();
    w->fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0666);w->used=0;w->ok=w->fd>=0;
    return w->ok;
}
static void seq_put(seq_t *w,const void *data,size_t n) {
    const uint8_t *p=data;
    while(w->ok && n) {
        size_t k=s->stage_size-w->used;if(k>n)k=n;
        memcpy(s->stage+w->used,p,k);w->used+=k;p+=k;n-=k;
        if(w->used==s->stage_size) { w->ok=io_full(w->fd,s->stage,w->used,true);w->used=0; }
    }
}
static bool seq_end(seq_t *w) {
    if(w->fd<0)return false;
    if(w->ok && w->used) w->ok=io_full(w->fd,s->stage,w->used,true);
    return finish_fd(w->fd,w->ok);
}
/* Sequential whole-file reader with read-to-EOF validation. */
typedef struct { int fd;size_t pos,len; } rd_t;
static bool rd_begin(rd_t *r,const char *path) {
    ra_drop();
    r->fd=open(path,O_RDONLY);r->pos=r->len=0;
    return r->fd>=0;
}
static bool rd_get(rd_t *r,void *dst,size_t n) {
    uint8_t *d=dst;
    while(n) {
        if(r->pos==r->len) {
            ssize_t got=read(r->fd,s->stage,s->stage_size);
            if(got<=0)return false;
            r->len=(size_t)got;r->pos=0;
        }
        size_t k=r->len-r->pos;if(k>n)k=n;
        memcpy(d,s->stage+r->pos,k);r->pos+=k;d+=k;n-=k;
    }
    return true;
}
static bool rd_end(rd_t *r,bool ok) { /* ok stays true only at exact EOF */
    uint8_t c;
    if(ok && (r->pos!=r->len || read(r->fd,&c,1)!=0))ok=false;
    if(close(r->fd)!=0)ok=false;
    return ok;
}

static esp_err_t crypt_record(bool encrypt,uint32_t seg,uint32_t block,record_t *r,uint8_t *plain) {
    aad_t aad={.domain={'V','L','T','B','L','K','2',0},.segment=seg,.block=block};
    memcpy(aad.uuid,s->root_record.uuid,16);
    if(encrypt) {
        vault_crypto_random(r->iv,12);
        return vault_gcm_encrypt(s->gcm,r->iv,12,(uint8_t*)&aad,sizeof(aad),plain,BLOCK_BYTES,r->ciphertext,r->tag,16);
    }
    return vault_gcm_decrypt(s->gcm,r->iv,12,(uint8_t*)&aad,sizeof(aad),r->ciphertext,BLOCK_BYTES,r->tag,16,plain);
}
static esp_err_t crypt_root(bool encrypt) {
    root_record_t *r=&s->root_record;
    if(encrypt) {
        vault_crypto_random(r->iv,12);
        return vault_gcm_encrypt(s->gcm,r->iv,12,(uint8_t*)r,24,(uint8_t*)&s->root,ROOT_BYTES,r->ciphertext,r->tag,16);
    }
    return vault_gcm_decrypt(s->gcm,r->iv,12,(uint8_t*)r,24,r->ciphertext,ROOT_BYTES,r->tag,16,(uint8_t*)&s->root);
}
static bool valid_root(void) {
    uint32_t sectors=s->root.sectors, fat=s->root.fat_sectors, spc=s->root.cluster_sectors;
    if(memcmp(s->root_record.magic,"VLTDSK2",8) || sectors<131072 || sectors>VAULT_DRIVE_MAX_SECTORS ||
       (sectors&2047) || !spc || spc>128 || (spc&(spc-1)) || !fat || (uint64_t)fat*2+32>=sectors) return false;
    uint64_t clusters=(sectors-32-2*fat)/spc;
    return clusters>=65525 && clusters<0x0ffffff5 && (uint64_t)fat*512>=(clusters+2)*4;
}
static bool save_root(void) {
    seq_t w;
    if(!seq_begin(&w,ROOT ".tmp"))return false;
    seq_put(&w,&s->root_record,sizeof(s->root_record));
    if(!seq_end(&w)) return false;
    unlink(ROOT ".bak");
    if(rename(ROOT,ROOT ".bak")!=0 && errno!=ENOENT) return false;
    if(rename(ROOT ".tmp",ROOT)!=0) { rename(ROOT ".bak",ROOT);return false; }
    unlink(ROOT ".bak");return true;
}
/* A new segment file is extended to its full size once, while free card
 * space is still contiguous. The file then stays in few fragments (FatFs
 * fast-seek keeps working) and later writes never allocate clusters.
 * Unwritten slots are never read: the authenticated map names valid ones. */
static int create_segment(const char *path,uint32_t seg) {
    int fd=open(path,O_RDWR|O_CREAT,0666);
    if(fd<0)return -1;
    uint64_t blocks=(uint64_t)s->root.sectors/8-(uint64_t)seg*SEGMENT_BLOCKS;
    if(blocks>SEGMENT_BLOCKS)blocks=SEGMENT_BLOCKS;
    off_t size=(off_t)((blocks+1)*sizeof(record_t));
    struct stat st;
    if(fstat(fd,&st)!=0 || (st.st_size<size && (lseek(fd,size-1,SEEK_SET)!=size-1 || write(fd,"",1)!=1))) {
        close(fd);return -1;
    }
    return fd;
}
static int open_segment_rw(uint32_t seg,bool fresh) {
    char path[160];segment_path(path,sizeof(path),seg);
    int fd=open(path,O_RDWR);
    if(fd<0 && fresh)fd=create_segment(path,seg);
    return fd;
}
/* An acknowledged write has a durable authenticated redo journal before any
 * primary data/map/root changes. Replay is idempotent; incomplete .tmp files
 * are never replayed. The physical SD FAT itself still needs safe removal. */
static bool apply_journal(void) {
    journal_header_t h;rd_t r;
    if(!rd_begin(&r,JOURNAL))return false;
    bool ok=rd_get(&r,&h,sizeof(h)) && rd_get(&r,&s->data_record,sizeof(s->data_record)) &&
        rd_get(&r,&s->map_record,sizeof(s->map_record)) && rd_get(&r,&s->root_record,sizeof(s->root_record));
    ok=rd_end(&r,ok);
    if(!ok || memcmp(h.magic,"VLTTXN2",8) || h.block>=SEGMENT_BLOCKS || h.new_segment>1 ||
       memcmp(h.uuid,s->root_record.uuid,16)) return false;
    if(vault_gcm_decrypt(s->gcm,h.iv,12,(uint8_t*)&h,36,NULL,0,h.tag,16,NULL)!=ESP_OK ||
       crypt_root(false)!=ESP_OK || !valid_root() ||
       (uint64_t)h.segment*SEGMENT_BLOCKS+h.block >= (uint64_t)s->root.sectors/8 ||
       !bit(s->root.created,h.segment) ||
       crypt_record(false,h.segment,UINT32_MAX,&s->map_record,s->map)!=ESP_OK || !bit(s->map,h.block) ||
       crypt_record(false,h.segment,h.block,&s->data_record,s->plain)!=ESP_OK) return false;
    if(h.new_segment) {
        for(uint32_t i=0;i<SEGMENT_BLOCKS;i++) if(i!=h.block && bit(s->map,i))return false;
    }
    close_reader();
    int fd=open_segment_rw(h.segment,h.new_segment);
    if(fd<0)return false;
    ok=staged_io(fd,(uint64_t)(h.block+1)*sizeof(record_t),&s->data_record,sizeof(s->data_record),true) &&
       staged_io(fd,0,&s->map_record,sizeof(s->map_record),true);
    if(!finish_fd(fd,ok) || vault_drive_test_stop(2) || !save_root() || vault_drive_test_stop(3))return false;
    /* If deletion fails, stop serving writes until next unlock replays it. */
    if(unlink(JOURNAL)!=0)return false;
    s_cached=s_map_cached=false;return true;
}
static entry_t *table(void) { return (entry_t*)(s->batch+sizeof(batch_prefix_t)); }
static esp_err_t batch_tag(bool encrypt,const uint8_t iv[12],uint8_t tag[16],uint32_t count) {
    size_t n=sizeof(batch_prefix_t)+count*sizeof(entry_t);
    if(encrypt) return vault_gcm_encrypt(s->gcm,iv,12,s->batch,n,NULL,0,NULL,tag,16);
    return vault_gcm_decrypt(s->gcm,iv,12,s->batch,n,NULL,0,tag,16,NULL);
}
/* Writes a validated batch into the segment files, then the root. Records
 * at consecutive file positions (a map and/or consecutive blocks) are written
 * as one span. Replay is idempotent, so a crash anywhere here is repaired by
 * the next open. */
static bool apply_batch(uint32_t count,bool write_root) {
    entry_t *t=table();
    close_reader();
    for(uint32_t i=0;i<count;) {
        uint32_t end=i+1;
        while(end<count && t[end].block!=UINT32_MAX)end++;
        int fd=open_segment_rw(t[i].segment,t[i].new_segment);
        if(fd<0)return false;
        bool ok=true;
        for(uint32_t j=i;ok && j<end;) {
            uint32_t pos=j==i?0:t[j].block+1,k=j+1;
            while(k<end && t[k].block+1==pos+(k-j))k++;
            ok=staged_io(fd,(uint64_t)pos*sizeof(record_t),&s->records[j],(size_t)(k-j)*sizeof(record_t),true);
            j=k;
        }
        if(!finish_fd(fd,ok))return false;
        i=end;
    }
    if(vault_drive_test_stop(2) || (write_root && !save_root()) || vault_drive_test_stop(3))return false;
    return unlink(JOURNAL)==0;
}
static bool replay_batch(rd_t *r,uint32_t *out_count,uint8_t iv[12],uint8_t tag[16]) {
    batch_prefix_t *p=(batch_prefix_t*)s->batch;entry_t *t=table();
    if(!rd_get(r,p,sizeof(*p)) || !rd_get(r,iv,12) || !rd_get(r,tag,16) ||
       memcmp(p->magic,"VLTTXN3",8) || !p->count || p->count>2*s->cap) return false;
    uint32_t n=p->count;
    if(!rd_get(r,t,n*sizeof(entry_t)) || !rd_get(r,s->records,n*sizeof(record_t)) ||
       !rd_get(r,&s->root_record,sizeof(s->root_record))) return false;
    *out_count=n;return true;
}
static bool validate_batch(uint32_t n,const uint8_t iv[12],uint8_t tag[16]) {
    batch_prefix_t *p=(batch_prefix_t*)s->batch;entry_t *t=table();
    if(batch_tag(false,iv,tag,n)!=ESP_OK || crypt_root(false)!=ESP_OK || !valid_root() ||
       memcmp(p->uuid,s->root_record.uuid,16)) return false;
    uint64_t blocks=(uint64_t)s->root.sectors/8;
    for(uint32_t i=0;i<n;) {
        uint32_t seg=t[i].segment,used=0;
        if(t[i].block!=UINT32_MAX || t[i].new_segment>1 || (i && seg<=t[i-1].segment) ||
           (uint64_t)seg*SEGMENT_BLOCKS>=blocks || !bit(s->root.created,seg) ||
           crypt_record(false,seg,UINT32_MAX,&s->records[i],s->map)!=ESP_OK) return false;
        bool fresh=t[i].new_segment;
        for(i++;i<n && t[i].block!=UINT32_MAX;i++,used++) {
            entry_t *d=&t[i];
            if(d->segment!=seg || d->new_segment || d->block>=SEGMENT_BLOCKS || (used && d->block<=d[-1].block) ||
               (uint64_t)seg*SEGMENT_BLOCKS+d->block>=blocks || !bit(s->map,d->block) ||
               crypt_record(false,seg,d->block,&s->records[i],s->plain)!=ESP_OK) return false;
        }
        if(!used)return false;
        if(fresh) { /* A new segment's map may only name blocks in this batch. */
            uint32_t bits=0;for(uint32_t b=0;b<SEGMENT_BLOCKS;b++)bits+=bit(s->map,b);
            if(bits!=used)return false;
        }
    }
    return true;
}
static bool replay_journal(void) {
    rd_t r;
    if(!rd_begin(&r,JOURNAL))return false;
    uint8_t magic[8];
    bool batch=rd_get(&r,magic,8) && !memcmp(magic,"VLTTXN3",8);
    close(r.fd);
    if(!batch)return apply_journal(); /* VLTTXN2 journal from older firmware */
    uint32_t count=0;uint8_t iv[12],tag[16];
    if(!rd_begin(&r,JOURNAL))return false;
    bool ok=rd_end(&r,replay_batch(&r,&count,iv,tag));
    s_cached=s_map_cached=false;
    return ok && validate_batch(count,iv,tag) && apply_batch(count,true);
}
static void put16(uint8_t *p,uint16_t v) { p[0]=v;p[1]=v>>8; }
static void put32(uint8_t *p,uint32_t v) { put16(p,v);put16(p+2,v>>16); }
/* Lazy initial FAT32 contents are deterministic. Authenticated allocation maps
 * distinguish these untouched blocks from missing/corrupted written data. */
static void initial_block(uint32_t block,uint8_t *p) {
    memset(p,0,BLOCK_BYTES);
    uint32_t fat=s->root.fat_sectors,data_start=32+2*fat;
    for(unsigned i=0;i<8;i++) {
        uint32_t sector=block*8+i;uint8_t *b=p+i*512;
        if(sector==0 || sector==6) {
            b[0]=0xeb;b[1]=0x58;b[2]=0x90;memcpy(b+3,"MSDOS5.0",8);
            put16(b+11,512);b[13]=s->root.cluster_sectors;put16(b+14,32);b[16]=2;b[21]=0xf8;
            put16(b+24,63);put16(b+26,255);put32(b+32,s->root.sectors);put32(b+36,fat);
            put32(b+44,2);put16(b+48,1);put16(b+50,6);b[64]=0x80;b[66]=0x29;
            memcpy(b+67,s->root_record.uuid,4);memcpy(b+71,"ESP32 VAULT",11);memcpy(b+82,"FAT32   ",8);
            b[510]=0x55;b[511]=0xaa;
        } else if(sector==1 || sector==7) {
            put32(b,0x41615252);put32(b+484,0x61417272);
            put32(b+488,(s->root.sectors-data_start)/s->root.cluster_sectors-1);
            put32(b+492,3);put32(b+508,0xaa550000);
        } else if(sector==32 || sector==32+fat) {
            put32(b,0x0ffffff8);put32(b+4,UINT32_MAX);put32(b+8,0x0fffffff);
        } else if(sector==data_start) { memcpy(b,"ESP32 VAULT",11);b[11]=8; }
    }
}
static void *big_calloc(size_t n) {
#ifdef ESP_PLATFORM
    return heap_caps_calloc(1,n,MALLOC_CAP_SPIRAM);
#else
    return calloc(1,n);
#endif
}
static uint8_t *stage_alloc(size_t *size) {
#ifdef ESP_PLATFORM
    for(size_t n=VAULT_DRIVE_STAGE_BYTES;n>=MIN_STAGE_BYTES;n/=2) {
        uint8_t *p=heap_caps_malloc(n,MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
        if(p) { *size=n;ESP_LOGI(TAG,"SD staging buffer: %u bytes internal DMA RAM",(unsigned)n);return p; }
    }
    /* Still correct from PSRAM, but SD transfers fall back to single sectors. */
    ESP_LOGW(TAG,"No internal DMA RAM for SD staging; drive I/O will be slow");
#endif
    *size=VAULT_DRIVE_STAGE_BYTES;
    return malloc(VAULT_DRIVE_STAGE_BYTES);
}
/* Larger volumes need larger clusters: 4 KiB clusters on a 64 GB drive
 * produce two ~60 MB FATs that Windows reads during mount over full-speed USB.
 * Only new volumes use this geometry; existing roots remain authoritative. */
static uint32_t initial_cluster_sectors(uint64_t sectors) {
    return sectors>=8388608?64:sectors>=1048576?8:1;
}
/* Clean mounts and read-only traffic do not need the write working set.
 * Recovery must accommodate a batch from a full-sized cache on any boot. */
static bool allocate_write_cache(bool recovery) {
    for (uint32_t cap = VAULT_DRIVE_CACHE_BLOCKS;; cap = FALLBACK_CACHE_BLOCKS) {
        s->cap = cap;
        s->dirty_plain = big_calloc((size_t)cap * BLOCK_BYTES);
        s->records = big_calloc(2 * (size_t)cap * sizeof(record_t));
        s->batch = big_calloc(batch_bytes(cap));
        s->dirty_block = calloc(cap, sizeof(uint32_t));
        s->order = calloc(cap, sizeof(uint16_t));
        if (s->dirty_plain && s->records && s->batch && s->dirty_block && s->order)
            return true;
        release(s->dirty_plain, (size_t)cap * BLOCK_BYTES);
        release(s->records, 2 * (size_t)cap * sizeof(record_t));
        release(s->batch, batch_bytes(cap));
        free(s->dirty_block);
        free(s->order);
        s->dirty_plain = s->batch = NULL;
        s->records = NULL;
        s->dirty_block = NULL;
        s->order = NULL;
        s->cap = 0;
        if (recovery || cap == FALLBACK_CACHE_BLOCKS) return false;
    }
}

esp_err_t vault_drive_open(const uint8_t key[32],bool create) {
    if(!key || s || (create && vault_drive_exists())) return ESP_ERR_INVALID_STATE;
    /* The small working set prefers the 8 MB PSRAM so it does not fail under
     * internal-RAM pressure; only the SD staging buffer must be internal. */
#ifdef ESP_PLATFORM
    s=heap_caps_calloc(1,sizeof(*s),MALLOC_CAP_SPIRAM);
    if(!s) {
        s=heap_caps_calloc(1,sizeof(*s),MALLOC_CAP_8BIT);
    }
#else
    s=calloc(1,sizeof(*s));
#endif
    if(!s) {
        return ESP_ERR_NO_MEM;
    }
    s->reader=-1;
    s->stage=stage_alloc(&s->stage_size);
    s->gcm=vault_gcm_create(key);
    if(!s->stage || !s->gcm) { drop();return ESP_ERR_NO_MEM; }
    if(create) {
        uint64_t total,free_bytes;
        if(esp_vfs_fat_info(VAULT_MOUNT_POINT,&total,&free_bytes)!=ESP_OK)goto fail;
        /* 2% reserve covers per-segment maps, filesystem cluster rounding,
         * journal/root backups and room for the legacy file area. */
        uint64_t sectors=free_bytes/100*98/sizeof(record_t)*8;
        if(sectors>VAULT_DRIVE_MAX_SECTORS)sectors=VAULT_DRIVE_MAX_SECTORS;
        sectors &= ~(uint64_t)2047;
        if(sectors<131072)goto fail;
        s->root.sectors=sectors;
        uint32_t spc=initial_cluster_sectors(sectors);
        s->root.cluster_sectors=spc;
        uint64_t numerator=4*(sectors-32+2*spc),denominator=512*spc+8;
        s->root.fat_sectors=(numerator+denominator-1)/denominator;
        memcpy(s->root_record.magic,"VLTDSK2",8);vault_crypto_random(s->root_record.uuid,16);
        if(!valid_root())goto fail;
        s_creating=true;return ESP_OK;
    }
    if (exists(JOURNAL)) {
        if (!allocate_write_cache(true)) { drop(); return ESP_ERR_NO_MEM; }
        if (!replay_journal()) goto fail;
    }
    if(!exists(ROOT))rename(ROOT ".bak",ROOT);
    rd_t r;
    if(!rd_begin(&r,ROOT))goto fail;
    bool ok=rd_end(&r,rd_get(&r,&s->root_record,sizeof(s->root_record)));
    if(!ok || crypt_root(false)!=ESP_OK || !valid_root())goto fail;
    s_ready=true;return ESP_OK;
fail:
    drop();return ESP_FAIL;
}
esp_err_t vault_drive_create_step(void) {
    if(!s_creating || !s)return ESP_ERR_INVALID_STATE;
    if(crypt_root(true)!=ESP_OK || !save_root()) { drop();return ESP_FAIL; }
    s_creating=false;s_ready=true;return ESP_OK;
}
/* One read-only descriptor stays open on the current segment so FatFs keeps
 * its fast-seek cluster map instead of reopening and walking the FAT chain. */
static int segment_reader(uint32_t seg) {
    if(s->reader>=0 && s->read_segment==seg)return s->reader;
    close_reader();
    char path[160];segment_path(path,sizeof(path),seg);
    s->reader=open(path,O_RDONLY);s->read_segment=seg;return s->reader;
}
/* Reads n consecutive records of a segment, starting at file position pos,
 * into the staging buffer with one read (one multi-sector SD command for the
 * whole sectors in the span). */
static bool fetch(uint32_t seg,uint32_t pos,uint32_t n) {
    int fd=segment_reader(seg);
    ra_drop();
    if(fd<0 || !seek_to(fd,(uint64_t)pos*sizeof(record_t)) ||
       !io_full(fd,s->stage,(size_t)n*sizeof(record_t),false)) return false;
    s->ra_valid=true;s->ra_segment=seg;s->ra_first=pos;s->ra_count=n;
#ifdef VAULT_DRIVE_TEST
    s_test_fetches++;
#endif
    return true;
}
static record_t *staged_record(uint32_t seg,uint32_t pos) {
    if(!s->ra_valid || s->ra_segment!=seg || pos<s->ra_first || pos-s->ra_first>=s->ra_count) return NULL;
    return (record_t*)(s->stage+(size_t)(pos-s->ra_first)*sizeof(record_t));
}
/* Decrypts one logical block into out (any 4 KB buffer). Sequential reads of
 * allocated blocks fetch up to a staging buffer of following records at once. */
static esp_err_t load_block(uint32_t block,uint8_t *out) {
    uint32_t seg=block/SEGMENT_BLOCKS,within=block%SEGMENT_BLOCKS;
    bool sequential=s->last_valid && block==s->last_block+1;
    s->last_block=block;s->last_valid=true;
    if(!s_map_cached || s_map_segment!=seg) {
        s_map_cached=false;
        if(bit(s->root.created,seg)) {
            record_t *r=staged_record(seg,0);
            if(!r && fetch(seg,0,1)) r=staged_record(seg,0);
            if(!r) { s_last_error="map_io";return ESP_FAIL; }
            if(crypt_record(false,seg,UINT32_MAX,r,s->map)!=ESP_OK) {
                s_last_error="map_auth";return ESP_FAIL;
            }
        } else memset(s->map,0,sizeof(s->map));
        s_map_segment=seg;s_map_cached=true;
    }
    if(!bit(s->map,within)) { initial_block(block,out);return ESP_OK; }
    record_t *r=staged_record(seg,within+1);
    if(!r) {
        uint32_t n=1,max=(uint32_t)(s->stage_size/sizeof(record_t));
        if(sequential) while(n<max && within+n<SEGMENT_BLOCKS && bit(s->map,within+n))n++;
        if(fetch(seg,within+1,n)) r=staged_record(seg,within+1);
        if(!r) { s_last_error="data_io";return ESP_FAIL; }
    }
    if(crypt_record(false,seg,within,r,out)!=ESP_OK) {
        s_last_error="data_auth";return ESP_FAIL;
    }
    return ESP_OK;
}
/* Plaintext of one block in s->plain, for partial-block reads and writes. */
static esp_err_t load_plain(uint32_t block) {
    if(s_cached && s_cache_block==block)return ESP_OK;
    s_cached=false;
    esp_err_t err=load_block(block,s->plain);
    if(err==ESP_OK) { s_cache_block=block;s_cached=true; }
    return err;
}
/* Commits every cached block: encrypt records and updated maps, write one
 * durable batch journal, then apply it. Callers hold the runtime gate. */
static esp_err_t flush_dirty(void) {
    uint32_t n=s->dirty_count;
    if(!n)return ESP_OK;
    s_cached=s_map_cached=false;
    for(uint32_t i=0;i<n;i++) { /* insertion sort of slots by block number */
        uint16_t v=i;uint32_t j=i;
        while(j && s->dirty_block[s->order[j-1]]>s->dirty_block[v]) { s->order[j]=s->order[j-1];j--; }
        s->order[j]=v;
    }
    entry_t *t=table();uint32_t count=0;bool root_changed=false;
    for(uint32_t i=0;i<n;) {
        uint32_t seg=s->dirty_block[s->order[i]]/SEGMENT_BLOCKS,map_entry=count++;
        bool fresh=!bit(s->root.created,seg);
        record_t *map_record=&s->records[map_entry];
        if(fresh) memset(s->map,0,sizeof(s->map));
        else {
            record_t *r=staged_record(seg,0);
            if(!r && fetch(seg,0,1)) r=staged_record(seg,0);
            if(!r || crypt_record(false,seg,UINT32_MAX,r,s->map)!=ESP_OK)return ESP_FAIL;
        }
        for(;i<n && s->dirty_block[s->order[i]]/SEGMENT_BLOCKS==seg;i++) {
            uint16_t slot=s->order[i];uint32_t within=s->dirty_block[slot]%SEGMENT_BLOCKS;
            setbit(s->map,within);t[count]=(entry_t){seg,within,0};
            if(crypt_record(true,seg,within,&s->records[count++],s->dirty_plain+(size_t)slot*BLOCK_BYTES)!=ESP_OK)return ESP_FAIL;
        }
        t[map_entry]=(entry_t){seg,UINT32_MAX,fresh};
        if(crypt_record(true,seg,UINT32_MAX,map_record,s->map)!=ESP_OK)return ESP_FAIL;
        if(fresh) { setbit(s->root.created,seg);root_changed=true; }
    }
    close_reader();
    batch_prefix_t *p=(batch_prefix_t*)s->batch;uint8_t iv[12],tag[16];
    memcpy(p->magic,"VLTTXN3",8);memcpy(p->uuid,s->root_record.uuid,16);p->count=count;p->reserved=0;
    vault_crypto_random(iv,12);
    if((root_changed && crypt_root(true)!=ESP_OK) || batch_tag(true,iv,tag,count)!=ESP_OK)return ESP_FAIL;
    seq_t w;
    if(!seq_begin(&w,JOURNAL ".tmp"))return ESP_FAIL;
    seq_put(&w,p,sizeof(*p));seq_put(&w,iv,12);seq_put(&w,tag,16);
    seq_put(&w,t,count*sizeof(entry_t));seq_put(&w,s->records,count*sizeof(record_t));
    seq_put(&w,&s->root_record,sizeof(s->root_record));
    if(!seq_end(&w) || rename(JOURNAL ".tmp",JOURNAL)!=0 || vault_drive_test_stop(1) || !apply_batch(count,root_changed))
        return ESP_FAIL;
    vault_secure_zero(s->dirty_plain,(size_t)n*BLOCK_BYTES);s->dirty_count=0;
    return ESP_OK;
}
esp_err_t vault_drive_flush(void) {
    if(!s_ready || !s)return ESP_ERR_INVALID_STATE;
    if(flush_dirty()!=ESP_OK) { s_last_error="flush";drop();return ESP_FAIL; }
    return ESP_OK;
}
/* Flushes cached writes first; a drive that cannot flush is still closed. */
void vault_drive_close(void) {
    if(s_ready && s && s->dirty_count) (void)flush_dirty();
    drop();
}
static uint8_t *cached_block(uint32_t block) {
    for(uint32_t i=0;i<s->dirty_count;i++) if(s->dirty_block[i]==block)return s->dirty_plain+(size_t)i*BLOCK_BYTES;
    return NULL;
}
static esp_err_t transfer(uint64_t offset,void *data,size_t size,bool write) {
    if(!s_ready || !s)return ESP_ERR_INVALID_STATE;
    if(write && s_read_only)return ESP_ERR_NOT_SUPPORTED;
    uint64_t capacity=(uint64_t)s->root.sectors*512;
    if((size && !data) || offset>capacity || size>capacity-offset)return ESP_ERR_INVALID_ARG;
    if (write && size && !s->dirty_plain && !allocate_write_cache(false)) {
        s_last_error = "cache_alloc";
        return ESP_ERR_NO_MEM;
    }
    uint8_t *p=data;
    while(size) {
        uint32_t block=offset/BLOCK_BYTES;size_t within=offset%BLOCK_BYTES,n=BLOCK_BYTES-within;if(n>size)n=size;
        uint8_t *cached=cached_block(block);
        if(write) {
            if(!cached) {
                /* A full cache is committed synchronously: USB back-pressure. */
                if(s->dirty_count==s->cap && flush_dirty()!=ESP_OK) { s_last_error="cache_full_flush";drop();return ESP_FAIL; }
                if(n<BLOCK_BYTES && load_plain(block)!=ESP_OK) { vault_drive_close();return ESP_FAIL; }
                uint32_t slot=s->dirty_count++;
                s->dirty_block[slot]=block;cached=s->dirty_plain+(size_t)slot*BLOCK_BYTES;
                if(n<BLOCK_BYTES) memcpy(cached,s->plain,BLOCK_BYTES);
            }
            memcpy(cached+within,p,n);
            if(s_cached && s_cache_block==block)s_cached=false;
        } else if(cached) memcpy(p,cached+within,n);
        else if(n==BLOCK_BYTES) { /* whole block: decrypt straight into the host buffer */
            if(load_block(block,p)!=ESP_OK) { vault_drive_close();return ESP_FAIL; }
        } else {
            if(load_plain(block)!=ESP_OK) { vault_drive_close();return ESP_FAIL; }
            memcpy(p,s->plain+within,n);
        }
        offset+=n;p+=n;size-=n;
    }
    return ESP_OK;
}
esp_err_t vault_drive_read(uint64_t offset,void *data,size_t size) { return transfer(offset,data,size,false); }
esp_err_t vault_drive_write(uint64_t offset,const void *data,size_t size) { return transfer(offset,(void*)data,size,true); }
