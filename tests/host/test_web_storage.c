#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "vault_web.c"
#include "tusb.h"
const char vault_index_start[] = "test";
extern int64_t host_time;
extern int host_commit_fail;
static httpd_req_t r;
static void call(const char *uri,int method,const char *body,const char *token,esp_err_t (*fn)(httpd_req_t *)) {
 memset(&r,0,sizeof(r));r.uri=uri;r.method=method;r.body=body;r.content_len=body?strlen(body):0;r.token=token;r.marker="1";r.user_ctx=(void*)fn;guarded_handler(&r);
}
int main(void) {
 assert(vault_runtime_init()==ESP_OK);assert(vault_config_init()==ESP_OK);assert(vault_storage_init()==ESP_OK);
 // Setup validation and SD write failures must not report wrong PIN or throttle retries.
 call("/api/unlock",HTTP_POST,"{\"pin\":\"1234\"}",NULL,api_unlock_handler);
 assert(strstr(r.status,"400") && strstr(r.response,"6–63") && s_failures==0);
 assert(mkdir(VAULT_DIR "/index.tmp",0700)==0);
 call("/api/unlock",HTTP_POST,"{\"pin\":\"123456\"}",NULL,api_unlock_handler);
 assert(strstr(r.status,"500") && strstr(r.response,"setup failed") && s_failures==0);
 assert(!vault_storage_is_provisioned() && !vault_storage_is_unlocked());
 assert(rmdir(VAULT_DIR "/index.tmp")==0);
 call("/api/unlock",HTTP_POST,"{\"pin\":\"123456\"}",NULL,api_unlock_handler);
 assert(strstr(r.response,"\"success\":true"));char token[65];strcpy(token,s_token);
 call("/api/settings",HTTP_GET,NULL,NULL,api_settings_get);assert(strstr(r.status,"401"));
 call("/api/settings",HTTP_GET,NULL,token,api_settings_get);assert(strstr(r.response,"MyEarPods"));assert(!strstr(r.response,"53cur3ty"));
 call("/api/settings",HTTP_POST,"{\"current_pin\":\"123456\",\"wifi_channel\":257}",token,api_settings_post);assert(strstr(r.status,"400"));
 call("/api/settings",HTTP_POST,"{\"current_pin\":\"123456\",\"wifi_ssid\":\"My vault\",\"auto_lock_sec\":30,\"led_mode\":2}",token,api_settings_post);assert(strstr(r.response,"\"success\":true"));
 vault_config_t cfg;vault_config_get(&cfg);assert(cfg.auto_lock_sec==30&&cfg.led_mode==2&&!strcmp(cfg.wifi_ssid,"My vault"));
 host_commit_fail=1;cfg.auto_lock_sec=60;assert(vault_config_save(&cfg)!=ESP_OK);vault_config_get(&cfg);assert(cfg.auto_lock_sec==30);host_commit_fail=0;
 // HTTP receive mock fragments every read at 13 bytes; stored blocks must still be 4096 bytes.
 char *data=malloc(9002);memset(data,'x',9001);data[9001]=0;
 call("/api/upload?name=notes%22%3Ctest%3E.txt",HTTP_POST,data,token,api_upload_handler);assert(strstr(r.response,"\"success\":true"));
 size_t count=0;assert(vault_storage_list_files(NULL,0,&count)==ESP_OK&&count==1);
 vault_file_record_t rec;vault_storage_list_files(&rec,1,&count);uint64_t total;uint32_t chunk,chunks;
 assert(vault_storage_download_begin(rec.file_id,&total,&chunk,&chunks)==ESP_OK&&total==9001&&chunks==3);
 unsigned char out[4096];size_t n;for(unsigned i=0;i<chunks;i++){assert(vault_storage_download_chunk(rec.file_id,i,out,&n)==ESP_OK);assert(n==(i<2?4096:809));for(size_t j=0;j<n;j++)assert(out[j]=='x');}vault_storage_download_end(rec.file_id);
 call("/api/files",HTTP_GET,NULL,token,api_files_handler);cJSON *files=cJSON_Parse(r.response);assert(files);cJSON_Delete(files);assert(strstr(r.response,"notes\\\"<test>.txt"));
 // Untrusted chunk lengths must fail before allocating/writing the fixed plaintext buffer.
 char hex[33], path[256];hex_encode(rec.file_id,16,hex);snprintf(path,sizeof(path),"%s/%s.bin",VAULT_FILES_DIR,hex);
 FILE *tamper=fopen(path,"r+b");assert(tamper);fseek(tamper,sizeof(vault_container_header_t)+4,SEEK_SET);uint32_t hostile=8192;fwrite(&hostile,1,4,tamper);fclose(tamper);
 assert(vault_storage_download_begin(rec.file_id,&total,&chunk,&chunks)==ESP_OK);assert(vault_storage_download_chunk(rec.file_id,0,out,&n)!=ESP_OK);vault_storage_download_end(rec.file_id);
 tamper=fopen(path,"r+b");assert(tamper);fseek(tamper,sizeof(vault_container_header_t)+4,SEEK_SET);hostile=4096;fwrite(&hostile,1,4,tamper);fclose(tamper);
 // Failed HTTP credentials incur a retry delay without damaging the active session.
 call("/api/unlock",HTTP_POST,"{\"pin\":\"wrong!\"}",NULL,api_unlock_handler);assert(strstr(r.response,"false"));
 call("/api/unlock",HTTP_POST,"{\"pin\":\"123456\"}",NULL,api_unlock_handler);assert(strstr(r.status,"429"));host_time+=40000000;
 // Wrong old credential must not replace or corrupt the active DEK.
 assert(vault_storage_change_pin("bad-pin","abcdef")!=ESP_OK);assert(vault_storage_change_pin("","abcdef")!=ESP_OK);
 assert(vault_storage_download_begin(rec.file_id,&total,&chunk,&chunks)==ESP_OK);assert(vault_storage_download_chunk(rec.file_id,0,out,&n)==ESP_OK);vault_storage_download_end(rec.file_id);
 assert(vault_storage_change_pin("123456","abcdef")==ESP_OK);
 vault_storage_lock();assert(vault_storage_unlock("123456")!=ESP_OK);assert(vault_storage_unlock("abcdef")==ESP_OK);
 // Incomplete upload cannot commit; empty upload must include an authenticated empty chunk.
 unsigned char id[16];assert(vault_storage_upload_begin("short.bin",4097,id)==ESP_OK);assert(vault_storage_upload_chunk(id,0,(uint8_t*)data,13)!=ESP_OK);assert(vault_storage_upload_commit(id)!=ESP_OK);vault_storage_upload_abort(id);
 assert(vault_storage_upload_begin("empty.bin",0,id)==ESP_OK);assert(vault_storage_upload_chunk(id,0,NULL,0)==ESP_OK);assert(vault_storage_upload_commit(id)==ESP_OK);
 // Authentication protects the zero-record index too, and unlock fails closed on corruption.
 assert(vault_storage_delete_file(rec.file_id)==ESP_OK);assert(vault_storage_delete_file(id)==ESP_OK);
 vault_storage_lock();FILE *fp=fopen(VAULT_INDEX_PATH,"r+b");assert(fp);assert(fseek(fp,-1,SEEK_END)==0);int c=fgetc(fp);fseek(fp,-1,SEEK_END);fputc(c^1,fp);fclose(fp);assert(vault_storage_unlock("abcdef")!=ESP_OK);assert(!vault_storage_is_unlocked());
 // Restore an empty authenticated index for idle timeout testing via a fresh test vault.
 remove(VAULT_META_PATH);remove(VAULT_INDEX_PATH);assert(vault_storage_create("abcdef")==ESP_OK);
 vault_runtime_touch();host_time+=31000000;vault_runtime_poll();assert(!vault_storage_is_unlocked());
 // Browser session expires on locking; the server does not trust stale tokens.
 call("/api/settings",HTTP_GET,NULL,token,api_settings_get);assert(strstr(r.status,"401"));
 // Host and Origin checks reject rebinding and foreign browser origins.
 call("/api/status",HTTP_GET,NULL,NULL,api_status_handler);
 assert(!strstr(r.response,"64000"));
 r.host="attacker.example";r.response[0]=0;r.status[0]=0;guarded_handler(&r);assert(strstr(r.status,"403"));
 r.host="192.168.4.1";r.origin="https://attacker.example";r.response[0]=0;r.status[0]=0;guarded_handler(&r);assert(strstr(r.status,"403"));
 r.origin="https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example";r.response[0]=0;r.status[0]=0;guarded_handler(&r);assert(strstr(r.status,"403"));
 // A valid tag followed by unauthenticated trailing bytes is rejected.
 vault_storage_lock();assert(vault_storage_unlock("abcdef")==ESP_OK);
 FILE *extra=fopen(VAULT_INDEX_PATH,"ab");assert(extra);fputc(0,extra);fclose(extra);
 vault_storage_lock();assert(vault_storage_unlock("abcdef")!=ESP_OK);assert(!vault_storage_is_unlocked());
 // Exported drive owns storage: browser locking/mutations must wait for eject.
 remove(VAULT_META_PATH);remove(VAULT_INDEX_PATH);assert(vault_storage_create("123456")==ESP_OK);
 call("/api/unlock",HTTP_POST,"{\"pin\":\"123456\"}",NULL,api_unlock_handler);strcpy(token,s_token);
 assert(vault_storage_drive_open(true)==ESP_OK && vault_drive_create_step()==ESP_OK);
 call("/api/lock",HTTP_POST,"{}",token,api_lock_handler);assert(strstr(r.status,"409") && vault_storage_is_unlocked());
 call("/api/upload?name=test.bin",HTTP_POST,"test",token,api_upload_handler);assert(strstr(r.status,"409"));
 call("/api/status",HTTP_GET,NULL,token,api_status_handler);assert(strstr(r.response,"\"usb_drive_ready\":true"));
 assert(tud_msc_start_stop_cb(0,0,false,true));
 // Write block: per-connection choice, saved default, and no switching while exported.
 call("/api/usb/connect",HTTP_POST,"{\"read_only\":1}",token,api_usb_connect);assert(strstr(r.status,"400") && !vault_msc_exported());
 call("/api/usb/connect",HTTP_POST,"[]",token,api_usb_connect);assert(strstr(r.status,"400") && !vault_msc_exported());
 call("/api/settings",HTTP_POST,"{\"current_pin\":\"123456\",\"usb_read_only\":true}",token,api_settings_post);assert(strstr(r.response,"\"success\":true"));
 call("/api/settings",HTTP_GET,NULL,token,api_settings_get);assert(strstr(r.response,"\"usb_read_only\":true"));
 call("/api/usb/connect",HTTP_POST,NULL,token,api_usb_connect);assert(strstr(r.response,"\"read_only\":true"));
 call("/api/status",HTTP_GET,NULL,token,api_status_handler);assert(strstr(r.response,"\"usb_drive_read_only\":true"));
 assert(!tud_msc_is_writable_cb(0));
 call("/api/usb/connect",HTTP_POST,"{\"read_only\":false}",token,api_usb_connect);assert(strstr(r.status,"409") && strstr(r.response,"switching"));
 call("/api/usb/connect",HTTP_POST,"{\"read_only\":true}",token,api_usb_connect);assert(strstr(r.response,"\"success\":true"));
 assert(tud_msc_start_stop_cb(0,0,false,true));
 call("/api/usb/connect",HTTP_POST,"{\"read_only\":false}",token,api_usb_connect);assert(strstr(r.response,"\"read_only\":false"));
 call("/api/status",HTTP_GET,NULL,token,api_status_handler);assert(strstr(r.response,"\"usb_drive_read_only\":false"));
 assert(tud_msc_is_writable_cb(0));
 assert(tud_msc_start_stop_cb(0,0,false,true));
 call("/api/lock",HTTP_POST,"{}",token,api_lock_handler);assert(!vault_storage_is_unlocked());
 free(data);puts("Host firmware regression checks passed (fragmented HTTP, sessions, settings, storage, credentials, idle lock, USB ownership)");return 0;
}
