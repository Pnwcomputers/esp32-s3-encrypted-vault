#include <assert.h>
#include "vault_drive.c"
#include "vault_msc.h"
#include "vault_runtime.h"
#include "vault_config.h"
#include "tusb.h"
extern int64_t host_time;
static unsigned stop_at;
bool vault_drive_test_stop(unsigned stage) { if(stage==stop_at){stop_at=0;return true;}return false; }
static uint32_t get32(const uint8_t *p) { return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static void flip(const char *path,long pos) {
    FILE *fp=fopen(path,"r+b");assert(fp);assert(fseek(fp,pos,SEEK_SET)==0);
    int c=fgetc(fp);assert(c!=EOF);assert(fseek(fp,pos,SEEK_SET)==0);assert(fputc(c^1,fp)!=EOF);assert(fclose(fp)==0);
}
int main(void) {
    assert(initial_cluster_sectors(262144)==1);
    assert(initial_cluster_sectors(1048576)==8);
    assert(initial_cluster_sectors(8388607)==8);
    assert(initial_cluster_sectors(8388608)==64);
    assert(initial_cluster_sectors(121376768)==64);
    assert(initial_cluster_sectors(242753536)==64);
    assert(vault_runtime_init()==ESP_OK && vault_config_init()==ESP_OK && vault_storage_init()==ESP_OK);
    assert(vault_storage_create("123456")==ESP_OK);
    assert(vault_storage_drive_open(true)==ESP_OK && vault_drive_creating());
    assert(vault_drive_create_step()==ESP_OK && vault_drive_ready());
    assert(vault_drive_sector_count()==262144);
    uint8_t data[8192],out[8192];for(unsigned i=0;i<sizeof(data);i++)data[i]=(i*37+19)%256;
    assert(vault_drive_read(0,out,512)==ESP_OK && out[510]==0x55 && out[511]==0xaa && !memcmp(out+82,"FAT32   ",8));
    uint32_t fat=get32(out+36),spc=out[13],sectors=get32(out+32);
    assert(sectors==262144 && (sectors-32-2*fat)/spc>=65525);
    assert(vault_drive_read(512,out,512)==ESP_OK && get32(out)==0x41615252 && get32(out+484)==0x61417272);
    assert(vault_drive_read(32*512,out,512)==ESP_OK && get32(out)==0x0ffffff8 && get32(out+8)==0x0fffffff);
    /* Export only synthetic test data for an independent FAT checker. */
    FILE *image=fopen(VAULT_MOUNT_POINT "/host-volume.img","wb");assert(image);
    assert(fseek(image,(long)sectors*512-1,SEEK_SET)==0 && fputc(0,image)!=EOF);
    for(uint32_t b=0;b<sectors/8;b++) {
        assert(vault_drive_read((uint64_t)b*4096,out,4096)==ESP_OK);
        bool nonzero=false;for(unsigned j=0;j<4096;j++)if(out[j]){nonzero=true;break;}
        if(nonzero)assert(fseek(image,(long)b*4096,SEEK_SET)==0 && fwrite(out,1,4096,image)==4096);
    }
    assert(fclose(image)==0);
    assert(vault_drive_write(4096*100+511,data,sizeof(data))==ESP_OK);
    assert(vault_drive_read(4096*100+511,out,sizeof(out))==ESP_OK && !memcmp(data,out,sizeof(data)));
    /* More dirty blocks than the cache holds: synchronous batch flushes, a new
     * segment mid-stream, then everything survives lock/unlock. */
    uint8_t block[4096];
    for(uint32_t b=0;b<3*VAULT_DRIVE_CACHE_BLOCKS;b++) {
        memset(block,(int)(b*7+1),sizeof(block));
        assert(vault_drive_write(((uint64_t)SEGMENT_BLOCKS-VAULT_DRIVE_CACHE_BLOCKS+b)*4096,block,sizeof(block))==ESP_OK);
    }
    assert(vault_drive_dirty());
    vault_storage_lock();assert(!exists(JOURNAL) && !exists(JOURNAL ".tmp"));
    assert(vault_storage_unlock("123456")==ESP_OK && vault_storage_drive_open(false)==ESP_OK && !vault_drive_dirty());
    for(uint32_t b=0;b<3*VAULT_DRIVE_CACHE_BLOCKS;b++) {
        assert(vault_drive_read(((uint64_t)SEGMENT_BLOCKS-VAULT_DRIVE_CACHE_BLOCKS+b)*4096,block,sizeof(block))==ESP_OK);
        for(unsigned j=0;j<sizeof(block);j++) assert(block[j]==(uint8_t)(b*7+1));
    }
    /* Cross a backing-file boundary, and preserve it across lock/unlock. */
    uint64_t boundary=(uint64_t)SEGMENT_BLOCKS*4096-100;
    assert(vault_drive_write(boundary,data,512)==ESP_OK);
    vault_storage_lock();assert(!vault_drive_ready());assert(vault_drive_read(0,out,1)==ESP_ERR_INVALID_STATE);
    assert(vault_storage_unlock("123456")==ESP_OK && vault_storage_drive_open(false)==ESP_OK);
    assert(vault_drive_read(boundary,out,512)==ESP_OK && !memcmp(data,out,512));
    assert(vault_drive_read(UINT64_MAX,out,512)==ESP_ERR_INVALID_ARG);
    assert(vault_drive_write((uint64_t)sectors*512-1,data,2)==ESP_ERR_INVALID_ARG);
    /* Interrupt after the durable journal, segment update, and root update.
     * Each new unlock must replay and recover the acknowledged-intent data. */
    for(unsigned stage=1;stage<=3;stage++) {
        stop_at=stage;data[0]=stage;
        assert(vault_drive_write(4096*100,data,512)==ESP_OK && vault_drive_dirty());
        assert(vault_drive_flush()!=ESP_OK && !vault_drive_ready());
        if(stage==1) { /* Also recover a missing/truncated primary header. */
            FILE *bad=fopen(ROOT,"wb");assert(bad);fclose(bad);
        }
        assert(vault_storage_drive_open(false)==ESP_OK);
        assert(vault_drive_read(4096*100,out,512)==ESP_OK && !memcmp(data,out,512));
        assert(!exists(JOURNAL));
    }
    /* Ciphertext and allocation metadata corruption must fail closed. */
    char path[160];segment_path(path,sizeof(path),0);
    long tag_offset=(long)(101)*sizeof(record_t)+12;
    vault_drive_close();flip(path,tag_offset);
    assert(vault_storage_drive_open(false)==ESP_OK);
    assert(vault_drive_read(4096*100,out,512)!=ESP_OK && !vault_drive_ready());
    assert(!strcmp(vault_drive_last_error(),"data_auth"));
    flip(path,tag_offset);assert(vault_storage_drive_open(false)==ESP_OK);
    vault_drive_close();flip(path,12);
    assert(vault_storage_drive_open(false)==ESP_OK && vault_drive_read(4096*100,out,512)!=ESP_OK);
    assert(!strcmp(vault_drive_last_error(),"map_auth"));
    flip(path,12);assert(vault_storage_drive_open(false)==ESP_OK);
    vault_drive_close();assert(rename(path,VAULT_DIR "/segment.saved")==0);
    assert(vault_storage_drive_open(false)==ESP_OK && vault_drive_read(4096*100,out,512)!=ESP_OK);
    assert(!strcmp(vault_drive_last_error(),"map_io"));
    assert(rename(VAULT_DIR "/segment.saved",path)==0);
    assert(vault_storage_drive_open(false)==ESP_OK);
    /* Actual MSC callbacks: capacity, ranges, lock gating, eject and idle lock. */
    uint32_t count;uint16_t size;tud_msc_capacity_cb(0,&count,&size);assert(count==sectors && size==512);
    assert(tud_msc_test_unit_ready_cb(0));assert(!tud_msc_test_unit_ready_cb(1));
    assert(tud_msc_write10_cb(0,900,0,data,512)==512);
    assert(tud_msc_read10_cb(0,900,0,out,512)==512 && !memcmp(data,out,512));
    assert(tud_msc_read10_cb(0,sectors,0,out,512)<0);
    vault_config_t cfg;vault_config_get(&cfg);cfg.auto_lock_sec=30;assert(vault_config_save(&cfg)==ESP_OK);
    host_time+=40000000;vault_runtime_poll();assert(vault_storage_is_unlocked());
    assert(tud_msc_start_stop_cb(0,0,false,true));assert(!vault_msc_exported());
    vault_runtime_poll();assert(!vault_storage_is_unlocked());
    assert(tud_msc_read10_cb(0,0,0,out,512)<0 && !tud_msc_is_writable_cb(0));
    tud_msc_capacity_cb(0,&count,&size);assert(count==0);
    /* Unlocking alone never exports the drive; only an explicit connect does. */
    assert(vault_storage_unlock("123456")==ESP_OK);
    assert(!tud_msc_test_unit_ready_cb(0) && !vault_msc_exported());
    assert(vault_msc_connect()==ESP_OK);
    assert(!tud_msc_test_unit_ready_cb(0));assert(tud_msc_test_unit_ready_cb(0));
    /* SYNCHRONIZE CACHE commits cached writes. */
    const uint8_t sync_cmd[16]={0x35};
    assert(tud_msc_write10_cb(0,901,0,data,512)==512 && vault_drive_dirty());
    assert(tud_msc_scsi_cb(0,sync_cmd,NULL,0)==0 && !vault_drive_dirty());
    assert(tud_msc_start_stop_cb(0,0,false,true));
    assert(vault_storage_change_pin("123456","abcdef")==ESP_OK);
    vault_storage_lock();assert(vault_storage_unlock("abcdef")==ESP_OK && vault_storage_drive_open(false)==ESP_OK);
    assert(vault_drive_read(900*512,out,512)==ESP_OK && !memcmp(data,out,512));
    vault_storage_lock();puts("Encrypted SD drive checks passed (FAT32, block IO, recovery, authentication, MSC, lock/eject)");
}
