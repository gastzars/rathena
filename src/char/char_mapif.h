/**
 * @file char_mapif.h
 * Module purpose is to handle incoming and outgoing requests with map-server.
 * Licensed under GNU GPL.
 *  For more information, see LICENCE in the main folder.
 * @author Athena Dev Teams originally in login.c
 * @author rAthena Dev Team
 */

#ifndef CHAR_MAPIF_H
#define	CHAR_MAPIF_H

#ifdef	__cplusplus
extern "C" {
#endif

int chmapif_sendall(unsigned char *buf, unsigned int len);
int chmapif_sendallwos(int sfd, unsigned char *buf, unsigned int len);
int chmapif_send(int fd, unsigned char *buf, unsigned int len);
int chmapif_send_fame_list(int fd);
void chmapif_update_fame_list(int type, int index, int fame);
void chmapif_sendall_playercount(int users);
int chmapif_parse_getmapname(int fd, int id);
int chmapif_parse_askscdata(int fd);
int chmapif_parse_getusercount(int fd, int id);
int chmapif_parse_regmapuser(int fd, int id);
int chmapif_parse_reqsavechar(int fd, int id);
int chmapif_parse_authok(int fd);
int chmapif_parse_req_saveskillcooldown(int fd);
int chmapif_parse_req_skillcooldown(int fd);
int chmapif_parse_reqchangemapserv(int fd);
int chmapif_parse_askrmfriend(int fd);
int chmapif_parse_reqcharname(int fd);
int chmapif_parse_reqnewemail(int fd);
int chmapif_parse_fwlog_changestatus(int fd);
int chmapif_parse_updfamelist(int fd);
void chmapif_send_ackdivorce(int partner_id1, int partner_id2);
int chmapif_parse_reqdivorce(int fd);
int chmapif_parse_updmapinfo(int fd);
int chmapif_parse_setcharoffline(int fd);
int chmapif_parse_setalloffline(int fd, int id);
int chmapif_parse_setcharonline(int fd, int id);
int chmapif_parse_reqfamelist(int fd);
int chmapif_parse_save_scdata(int fd);
int chmapif_parse_keepalive(int fd);
int chmapif_parse_reqauth(int fd, int id);
int chmapif_parse_updmapip(int fd, int id);

int chmapif_vipack(int mapfd, uint32 aid, uint32 vip_time, uint32 groupid, uint8 flag);
int chmapif_parse_reqcharban(int fd);
int chmapif_parse_reqcharunban(int fd);
int chmapif_bonus_script_get(int fd);
int chmapif_bonus_script_save(int fd);

void chmapif_connectack(int fd, uint8 errCode);
void chmapif_charselres(int fd, uint32 aid, uint8 res);
void chmapif_changemapserv_ack(int fd, bool nok);

int chmapif_parse(int fd);
int chmapif_init(int fd);
void chmapif_server_init(int id);
void chmapif_server_destroy(int id);
void do_init_chmapif(void);
void chmapif_server_reset(int id);
void chmapif_on_disconnect(int id);
void do_final_chmapif(void);
int chmapif_parse_gepard_block(int fd);
int chmapif_parse_gepard_unblock(int fd);


#ifdef	__cplusplus
}
#endif

#endif	/* CHAR_MAPIF_H */

