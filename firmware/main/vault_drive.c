#include "vault_drive.h"
#include "vault_storage.h"
#include "vault_crypto.h"
#include "esp_vfs_fat.h"
#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define ROOT VAULT_DIR "/usb-drive.hdr"
#define JOURNAL VAULT_DIR "/usb-drive.txn"
#define SEGMENT_BLOCKS 16384U
#define ROOT_BYTES 8192U
#define BLOCK_BYTES 4096U
/* ESP-IDF's small default stdio buffer splits encrypted records into many
 * SD transactions. Buffer both journal writes and segment reads/writes. */
#define DRIVE_IO_BUFFER_BYTES (16U * 1024U)
static FILE *drive_fopen(const char *path,const char *mode) {
    FILE *fp=fopen(path,mode);
    if(fp && setvbuf(fp,NULL,_IOFBF,DRIVE_IO_BUFFER_BYTES)!=0) {
        fclose(fp);return NULL;
    }
    return fp;
}
#ifdef VAULT_DRIVE_TEST
extern bool vault_drive_test_stop(unsigned stage);
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
static struct {
    root_plain_t root;
    root_record_t root_record;
    record_t data_record, map_record;
    uint8_t map[BLOCK_BYTES], plain[BLOCK_BYTES];
    uint32_t cap, dirty_count, read_segment;
    uint32_t *dirty_block;
    uint16_t *order;
    uint8_t *dirty_plain, *batch; /* batch: prefix followed by the entry table */
    record_t *records;
    FILE *reader;
} *s;
static uint8_t s_key[32];
static const char *s_last_error="none";
const char *vault_drive_last_error(void) { return s_last_error; }
static bool s_ready,s_creating,s_cached,s_map_cached;
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
static void close_reader(void) { if(s && s->reader) { fclose(s->reader);s->reader=NULL; } }
static void release(void *p,size_t n) { if(p) { vault_secure_zero(p,n);free(p); } }
static size_t batch_bytes(uint32_t cap) { return sizeof(batch_prefix_t)+2*cap*sizeof(entry_t); }
/* Frees everything, discarding any unflushed blocks; used on failure paths. */
static void drop(void) {
    s_ready=s_creating=s_cached=s_map_cached=false;
    vault_secure_zero(s_key,sizeof(s_key));
    if(s) {
        close_reader();
        release(s->dirty_plain,(size_t)s->cap*BLOCK_BYTES);release(s->records,2*(size_t)s->cap*sizeof(record_t));
        release(s->batch,batch_bytes(s->cap));free(s->dirty_block);free(s->order);
        vault_secure_zero(s,sizeof(*s));free(s);s=NULL;
    }
}
bool vault_drive_dirty(void) { return s && s->dirty_count; }
static bool finish(FILE *fp,bool ok) {
    if(fflush(fp)!=0) ok=false;
    if(fsync(fileno(fp))!=0) ok=false;
    if(fclose(fp)!=0) ok=false;
    return ok;
}
static esp_err_t crypt_record(bool encrypt,uint32_t seg,uint32_t block,record_t *r,uint8_t *plain) {
    aad_t aad={.domain={'V','L','T','B','L','K','2',0},.segment=seg,.block=block};
    memcpy(aad.uuid,s->root_record.uuid,16);
    if(encrypt) {
        vault_crypto_random(r->iv,12);
        return vault_crypto_aes_gcm_encrypt(s_key,r->iv,12,(uint8_t*)&aad,sizeof(aad),plain,BLOCK_BYTES,r->ciphertext,r->tag,16);
    }
    return vault_crypto_aes_gcm_decrypt(s_key,r->iv,12,(uint8_t*)&aad,sizeof(aad),r->ciphertext,BLOCK_BYTES,r->tag,16,plain);
}
static esp_err_t crypt_root(bool encrypt) {
    root_record_t *r=&s->root_record;
    if(encrypt) {
        vault_crypto_random(r->iv,12);
        return vault_crypto_aes_gcm_encrypt(s_key,r->iv,12,(uint8_t*)r,24,(uint8_t*)&s->root,ROOT_BYTES,r->ciphertext,r->tag,16);
    }
    return vault_crypto_aes_gcm_decrypt(s_key,r->iv,12,(uint8_t*)r,24,r->ciphertext,ROOT_BYTES,r->tag,16,(uint8_t*)&s->root);
}
static bool valid_root(void) {
    uint32_t sectors=s->root.sectors, fat=s->root.fat_sectors, spc=s->root.cluster_sectors;
    if(memcmp(s->root_record.magic,"VLTDSK2",8) || sectors<131072 || sectors>VAULT_DRIVE_MAX_SECTORS ||
       (sectors&2047) || !spc || spc>128 || (spc&(spc-1)) || !fat || (uint64_t)fat*2+32>=sectors) return false;
    uint64_t clusters=(sectors-32-2*fat)/spc;
    return clusters>=65525 && clusters<0x0ffffff5 && (uint64_t)fat*512>=(clusters+2)*4;
}
static bool save_root(void) {
    FILE *fp=drive_fopen(ROOT ".tmp","wb");if(!fp)return false;
    if(!finish(fp,fwrite(&s->root_record,1,sizeof(s->root_record),fp)==sizeof(s->root_record))) return false;
    unlink(ROOT ".bak");
    if(rename(ROOT,ROOT ".bak")!=0 && errno!=ENOENT) return false;
    if(rename(ROOT ".tmp",ROOT)!=0) { rename(ROOT ".bak",ROOT);return false; }
    unlink(ROOT ".bak");return true;
}
/* An acknowledged write has a durable authenticated redo journal before any
 * primary data/map/root changes. Replay is idempotent; incomplete .tmp files
 * are never replayed. The physical SD FAT itself still needs safe removal. */
static bool apply_journal(void) {
    journal_header_t h;
    FILE *fp=drive_fopen(JOURNAL,"rb");if(!fp)return false;
    bool ok=fread(&h,1,sizeof(h),fp)==sizeof(h) &&
        fread(&s->data_record,1,sizeof(s->data_record),fp)==sizeof(s->data_record) &&
        fread(&s->map_record,1,sizeof(s->map_record),fp)==sizeof(s->map_record) &&
        fread(&s->root_record,1,sizeof(s->root_record),fp)==sizeof(s->root_record) && fgetc(fp)==EOF;
    if(fclose(fp)!=0)ok=false;
    if(!ok || memcmp(h.magic,"VLTTXN2",8) || h.block>=SEGMENT_BLOCKS || h.new_segment>1 ||
       memcmp(h.uuid,s->root_record.uuid,16)) return false;
    if(vault_crypto_aes_gcm_decrypt(s_key,h.iv,12,(uint8_t*)&h,36,NULL,0,h.tag,16,NULL)!=ESP_OK ||
       crypt_root(false)!=ESP_OK || !valid_root() ||
       (uint64_t)h.segment*SEGMENT_BLOCKS+h.block >= (uint64_t)s->root.sectors/8 ||
       !bit(s->root.created,h.segment) ||
       crypt_record(false,h.segment,UINT32_MAX,&s->map_record,s->map)!=ESP_OK || !bit(s->map,h.block) ||
       crypt_record(false,h.segment,h.block,&s->data_record,s->plain)!=ESP_OK) return false;
    if(h.new_segment) {
        for(uint32_t i=0;i<SEGMENT_BLOCKS;i++) if(i!=h.block && bit(s->map,i))return false;
    }
    char path[160];segment_path(path,sizeof(path),h.segment);
    fp=drive_fopen(path,"r+b");
    if(!fp && h.new_segment) fp=drive_fopen(path,"w+b");
    if(!fp)return false;
    long pos=(long)(h.block+1)*sizeof(record_t);
    ok=fseek(fp,pos,SEEK_SET)==0 && fwrite(&s->data_record,1,sizeof(s->data_record),fp)==sizeof(s->data_record) &&
       fseek(fp,0,SEEK_SET)==0 && fwrite(&s->map_record,1,sizeof(s->map_record),fp)==sizeof(s->map_record);
    if(!finish(fp,ok) || vault_drive_test_stop(2) || !save_root() || vault_drive_test_stop(3))return false;
    /* If deletion fails, stop serving writes until next unlock replays it. */
    if(unlink(JOURNAL)!=0)return false;
    s_cached=s_map_cached=false;return true;
}
static entry_t *table(void) { return (entry_t*)(s->batch+sizeof(batch_prefix_t)); }
static esp_err_t batch_tag(bool encrypt,const uint8_t iv[12],uint8_t tag[16],uint32_t count) {
    size_t n=sizeof(batch_prefix_t)+count*sizeof(entry_t);
    if(encrypt) return vault_crypto_aes_gcm_encrypt(s_key,iv,12,s->batch,n,NULL,0,NULL,tag,16);
    return vault_crypto_aes_gcm_decrypt(s_key,iv,12,s->batch,n,NULL,0,tag,16,NULL);
}
/* Writes a validated batch into the segment files, then the root. Replay is
 * idempotent, so a crash anywhere here is repaired by the next open. */
static bool apply_batch(uint32_t count,bool write_root) {
    entry_t *t=table();
    for(uint32_t i=0;i<count;) {
        char path[160];segment_path(path,sizeof(path),t[i].segment);
        FILE *fp=drive_fopen(path,"r+b");
        if(!fp && t[i].new_segment) fp=drive_fopen(path,"w+b");
        if(!fp)return false;
        bool ok=fseek(fp,0,SEEK_SET)==0 && fwrite(&s->records[i],1,sizeof(record_t),fp)==sizeof(record_t);
        for(i++;i<count && t[i].block!=UINT32_MAX;i++)
            ok=ok && fseek(fp,(long)(t[i].block+1)*sizeof(record_t),SEEK_SET)==0 &&
               fwrite(&s->records[i],1,sizeof(record_t),fp)==sizeof(record_t);
        if(!finish(fp,ok))return false;
    }
    if(vault_drive_test_stop(2) || (write_root && !save_root()) || vault_drive_test_stop(3))return false;
    return unlink(JOURNAL)==0;
}
static bool replay_batch(FILE *fp,uint32_t *out_count) {
    batch_prefix_t *p=(batch_prefix_t*)s->batch;entry_t *t=table();uint8_t iv[12],tag[16];
    if(fread(p,1,sizeof(*p),fp)!=sizeof(*p) || fread(iv,1,12,fp)!=12 || fread(tag,1,16,fp)!=16 ||
       memcmp(p->magic,"VLTTXN3",8) || !p->count || p->count>2*s->cap) return false;
    uint32_t n=p->count;
    if(fread(t,sizeof(entry_t),n,fp)!=n || fread(s->records,sizeof(record_t),n,fp)!=n ||
       fread(&s->root_record,1,sizeof(s->root_record),fp)!=sizeof(s->root_record) || fgetc(fp)!=EOF ||
       batch_tag(false,iv,tag,n)!=ESP_OK || crypt_root(false)!=ESP_OK || !valid_root() ||
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
    *out_count=n;return true;
}
static bool replay_journal(void) {
    FILE *fp=drive_fopen(JOURNAL,"rb");if(!fp)return false;
    uint8_t magic[8];
    bool batch=fread(magic,1,8,fp)==8 && !memcmp(magic,"VLTTXN3",8);
    uint32_t count=0;bool ok=batch && fseek(fp,0,SEEK_SET)==0 && replay_batch(fp,&count);
    if(fclose(fp)!=0)ok=false;
    if(!batch)return apply_journal(); /* VLTTXN2 journal from older firmware */
    s_cached=s_map_cached=false;
    return ok && apply_batch(count,true);
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
/* Larger volumes need larger clusters: 4 KiB clusters on a 64 GB drive
 * produce two ~60 MB FATs that Windows reads during mount over full-speed USB.
 * Only new volumes use this geometry; existing roots remain authoritative. */
static uint32_t initial_cluster_sectors(uint64_t sectors) {
    return sectors>=8388608?64:sectors>=1048576?8:1;
}
esp_err_t vault_drive_open(const uint8_t key[32],bool create) {
    if(!key || s || (create && vault_drive_exists())) return ESP_ERR_INVALID_STATE;
    /* Allocate the ~32 KB working set at runtime, preferring the 8 MB PSRAM so it
     * does not fail under internal-RAM pressure; fall back to internal RAM if
     * PSRAM is unavailable. Nothing here is statically sized. */
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
    /* The write cache and batch buffers (~1.6 MB) need PSRAM; without it a
     * small internal-RAM cache still works, just with smaller batches. */
    for(uint32_t cap=VAULT_DRIVE_CACHE_BLOCKS;;cap=FALLBACK_CACHE_BLOCKS) {
        s->cap=cap;
        s->dirty_plain=big_calloc((size_t)cap*BLOCK_BYTES);
        s->records=big_calloc(2*(size_t)cap*sizeof(record_t));
        s->batch=big_calloc(batch_bytes(cap));
        s->dirty_block=calloc(cap,sizeof(uint32_t));s->order=calloc(cap,sizeof(uint16_t));
        if(s->dirty_plain && s->records && s->batch && s->dirty_block && s->order)break;
        release(s->dirty_plain,(size_t)cap*BLOCK_BYTES);release(s->records,2*(size_t)cap*sizeof(record_t));
        release(s->batch,batch_bytes(cap));free(s->dirty_block);free(s->order);
        s->dirty_plain=s->batch=NULL;s->records=NULL;s->dirty_block=NULL;s->order=NULL;
        if(cap==FALLBACK_CACHE_BLOCKS) { drop();return ESP_ERR_NO_MEM; }
    }
    memcpy(s_key,key,32);
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
    if(exists(JOURNAL) && !replay_journal())goto fail;
    if(!exists(ROOT))rename(ROOT ".bak",ROOT);
    FILE *fp=drive_fopen(ROOT,"rb");if(!fp)goto fail;
    bool ok=fread(&s->root_record,1,sizeof(s->root_record),fp)==sizeof(s->root_record) && fgetc(fp)==EOF;
    if(fclose(fp)!=0)ok=false;
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
/* One read handle stays open on the current segment so sequential reads seek
 * forward instead of reopening the file and walking its FAT chain each time. */
static FILE *segment_reader(uint32_t seg) {
    if(s->reader && s->read_segment==seg)return s->reader;
    close_reader();
    char path[160];segment_path(path,sizeof(path),seg);
    s->reader=drive_fopen(path,"rb");s->read_segment=seg;return s->reader;
}
static esp_err_t load_block(uint32_t block) {
    if(s_cached && s_cache_block==block)return ESP_OK;
    s_cached=false;uint32_t seg=block/SEGMENT_BLOCKS,within=block%SEGMENT_BLOCKS;
    if(!s_map_cached || s_map_segment!=seg) {
        s_map_cached=false;
        if(bit(s->root.created,seg)) {
            FILE *fp=segment_reader(seg);
            if(!fp || fseek(fp,0,SEEK_SET)!=0 || fread(&s->map_record,1,sizeof(s->map_record),fp)!=sizeof(s->map_record)) {
                s_last_error="map_io";return ESP_FAIL;
            }
            if(crypt_record(false,seg,UINT32_MAX,&s->map_record,s->map)!=ESP_OK) {
                s_last_error="map_auth";return ESP_FAIL;
            }
        } else memset(s->map,0,sizeof(s->map));
        s_map_segment=seg;s_map_cached=true;
    }
    if(bit(s->map,within)) {
        FILE *fp=segment_reader(seg);
        if(!fp || fseek(fp,(long)(within+1)*sizeof(record_t),SEEK_SET)!=0 ||
           fread(&s->data_record,1,sizeof(s->data_record),fp)!=sizeof(s->data_record)) {
            s_last_error="data_io";return ESP_FAIL;
        }
        if(crypt_record(false,seg,within,&s->data_record,s->plain)!=ESP_OK) {
            s_last_error="data_auth";return ESP_FAIL;
        }
    } else initial_block(block,s->plain);
    s_cache_block=block;s_cached=true;return ESP_OK;
}
/* Commits every cached block: encrypt records and updated maps, write one
 * durable batch journal, then apply it. Callers hold the runtime gate. */
static esp_err_t flush_dirty(void) {
    uint32_t n=s->dirty_count;
    if(!n)return ESP_OK;
    close_reader();s_cached=s_map_cached=false;
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
            FILE *fp=segment_reader(seg);
            bool ok=fp && fseek(fp,0,SEEK_SET)==0 && fread(map_record,1,sizeof(*map_record),fp)==sizeof(*map_record) &&
                crypt_record(false,seg,UINT32_MAX,map_record,s->map)==ESP_OK;
            close_reader();
            if(!ok)return ESP_FAIL;
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
    batch_prefix_t *p=(batch_prefix_t*)s->batch;uint8_t iv[12],tag[16];
    memcpy(p->magic,"VLTTXN3",8);memcpy(p->uuid,s->root_record.uuid,16);p->count=count;p->reserved=0;
    vault_crypto_random(iv,12);
    if((root_changed && crypt_root(true)!=ESP_OK) || batch_tag(true,iv,tag,count)!=ESP_OK)return ESP_FAIL;
    FILE *fp=drive_fopen(JOURNAL ".tmp","wb");if(!fp)return ESP_FAIL;
    bool ok=fwrite(p,1,sizeof(*p),fp)==sizeof(*p) && fwrite(iv,1,12,fp)==12 && fwrite(tag,1,16,fp)==16 &&
        fwrite(t,sizeof(entry_t),count,fp)==count && fwrite(s->records,sizeof(record_t),count,fp)==count &&
        fwrite(&s->root_record,1,sizeof(s->root_record),fp)==sizeof(s->root_record);
    if(!finish(fp,ok) || rename(JOURNAL ".tmp",JOURNAL)!=0 || vault_drive_test_stop(1) || !apply_batch(count,root_changed))
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
    uint64_t capacity=(uint64_t)s->root.sectors*512;
    if((size && !data) || offset>capacity || size>capacity-offset)return ESP_ERR_INVALID_ARG;
    uint8_t *p=data;
    while(size) {
        uint32_t block=offset/BLOCK_BYTES;size_t within=offset%BLOCK_BYTES,n=BLOCK_BYTES-within;if(n>size)n=size;
        uint8_t *cached=cached_block(block);
        if(write) {
            if(!cached) {
                /* A full cache is committed synchronously: USB back-pressure. */
                if(s->dirty_count==s->cap && flush_dirty()!=ESP_OK) { s_last_error="cache_full_flush";drop();return ESP_FAIL; }
                if(n<BLOCK_BYTES && load_block(block)!=ESP_OK) { vault_drive_close();return ESP_FAIL; }
                uint32_t slot=s->dirty_count++;
                s->dirty_block[slot]=block;cached=s->dirty_plain+(size_t)slot*BLOCK_BYTES;
                if(n<BLOCK_BYTES) memcpy(cached,s->plain,BLOCK_BYTES);
            }
            memcpy(cached+within,p,n);
            if(s_cached && s_cache_block==block)s_cached=false;
        } else if(cached) memcpy(p,cached+within,n);
        else {
            if(load_block(block)!=ESP_OK) { vault_drive_close();return ESP_FAIL; }
            memcpy(p,s->plain+within,n);
        }
        offset+=n;p+=n;size-=n;
    }
    return ESP_OK;
}
esp_err_t vault_drive_read(uint64_t offset,void *data,size_t size) { return transfer(offset,data,size,false); }
esp_err_t vault_drive_write(uint64_t offset,const void *data,size_t size) { return transfer(offset,(void*)data,size,true); }
