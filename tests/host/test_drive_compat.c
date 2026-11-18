/* Built twice: once with the previous release's vault_drive.c and once with
 * the current one (DRIVE_SRC). Each step runs as a separate process on the
 * same directory, proving the on-card format and journal replay are
 * compatible in both directions:
 *   old-write:  create a volume, commit data, leave a pending VLTTXN3 journal
 *   new-verify: replay that journal, verify, write more (incl. a new segment)
 *   old-verify: verify everything the current code wrote */
#include <assert.h>
#include DRIVE_SRC
static unsigned stop_at;
bool vault_drive_test_stop(unsigned stage) { if(stage==stop_at){stop_at=0;return true;}return false; }
static const uint8_t key[32]={9,8,7,6,5,4,3,2,1};
static void fill(uint8_t *p,size_t n,unsigned seed) { for(size_t i=0;i<n;i++)p[i]=(uint8_t)(i*31+seed*7+(i>>9)); }
static void check(uint64_t off,size_t n,unsigned seed) {
    static uint8_t want[65536],got[65536];assert(n<=sizeof(got));
    fill(want,n,seed);assert(vault_drive_read(off,got,n)==ESP_OK);assert(!memcmp(want,got,n));
}
static void put(uint64_t off,size_t n,unsigned seed) {
    static uint8_t data[65536];assert(n<=sizeof(data));fill(data,n,seed);assert(vault_drive_write(off,data,n)==ESP_OK);
}
#define SEG_BYTES ((uint64_t)SEGMENT_BLOCKS*4096)
int main(int argc,char **argv) {
    assert(argc==2);
    assert(mkdir(VAULT_DIR,0700)==0 || errno==EEXIST);
    if(!strcmp(argv[1],"old-write")) {
        assert(vault_drive_open(key,true)==ESP_OK && vault_drive_create_step()==ESP_OK);
        put(4096*50,65536,1);put(4096*100+700,9000,2);put(SEG_BYTES-12000,12000,3);
        assert(vault_drive_flush()==ESP_OK);
        put(4096*60+100,5000,4); /* committed journal, segment never updated */
        stop_at=1;assert(vault_drive_flush()!=ESP_OK);
        assert(exists(JOURNAL));
    } else if(!strcmp(argv[1],"new-verify")) {
        assert(vault_drive_open(key,false)==ESP_OK && !exists(JOURNAL));
    } else if(!strcmp(argv[1],"new-write")) {
        assert(vault_drive_open(key,false)==ESP_OK);
        put(SEG_BYTES+4096*3,40000,5);put(4096*200,4096*12,6);
        assert(vault_drive_flush()==ESP_OK);
        /* The new segment was preallocated to its full size in one step. */
        char path[160];segment_path(path,sizeof(path),1);struct stat st;
        assert(stat(path,&st)==0 && st.st_size==(off_t)(SEGMENT_BLOCKS+1)*sizeof(record_t));
        check(SEG_BYTES+4096*3,40000,5);check(4096*200,4096*12,6);
    } else if(!strcmp(argv[1],"old-verify")) {
        assert(vault_drive_open(key,false)==ESP_OK);
        check(SEG_BYTES+4096*3,40000,5);check(4096*200,4096*12,6);
        vault_drive_close();
        return 0;
    }
    if(strcmp(argv[1],"old-write")) {
        /* Every step after creation must still see the first writes. */
        uint8_t first[65536];fill(first,65536,1);
        static uint8_t got[65536];assert(vault_drive_read(4096*50,got,65536)==ESP_OK);
        uint8_t merged[65536];memcpy(merged,first,65536);
        uint8_t late[5000];fill(late,5000,4);memcpy(merged+(4096*60+100-4096*50),late,5000);
        assert(!memcmp(merged,got,65536));
        check(4096*100+700,9000,2);check(SEG_BYTES-12000,12000,3);
    }
    vault_drive_close();
    return 0;
}
