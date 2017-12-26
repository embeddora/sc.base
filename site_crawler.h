/*
 * Copyright (c) 2018 [n/a] info@embeddora.com All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of The Linux Foundation nor
 *          the names of its contributors may be used to endorse or promote
 *          products derived from this software without specific prior written
 *          permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.    IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _SITE_CRAWLER_H_
#define _SITE_CRAWLER_H_

#include <curl/curl.h>


/* Report #30, general success */
#define R30_SUCCESS		0

/* Report #30, general case failure */
#define R30_FAILURE		(-1)

/* Report #30, string length, single words: verbs and abbreviations */
#define R30_STRNLEN		80

/* Report #30, general purposed timeout; nice to have it's different kinds of site-opearions */
#define R30_GP_TMO		2




/* Report #30, String tocken length; */
#define R30_TKN_LENGTH		32

/* String tocken wrapper length; same as strlen("stok="); */
#define R30_TKN_WRP_LENGTH	5



/* TODO: give a comment */
#define R30_PSW_LENGTH		256

/* TODO: give a comment */
#define R30_PSW_SP_LENGTH	6



/* Report #30, TODO string length */
#define R30_CKY_LENGTH		32

/* Report #30, string tocken wrapper length; same as strlen("sysauth="); */
#define R30_WRP_CKY_LENGTH	8

/* Report #30 traffic disignator, should be unique among the existing User-Agents */
#define R30_CKY_MARKER		"MAZUKOWITZ-2450"




/* Max len of HTTP request */
#define R30_HTTP_LENGTH		0x200


/* Alternatively, use <node> */
#define INTERPRETER_FNAME	"nodejs"

/* Java script obtained via HTTP form P5 with minor custom amends */
#define RSA_COMPUTER_FNAME	"site_rsa.js"

/* File lenth; let's have it exactly what it should be */
#define R30_RSA_LEN		0x100


/* File to catch computed RSA-value to */
#define ENCR_FNAME		"_delme.rsa"

/* File to store cookie(s) being found diring run*/
#define CKY_FNAME		"_delme.cky"

/* File to store tocken as is and wrapped one being found diring run */
#define TOKEN_FNAME		"_delme.tkn"

/* File to store passwords as they're been fond while diring run */
#define PASSWD_FNAME		"_delme.psw"

/* Max length of system commands we launch in external shell (bash, sh, ksh, usw) */
#define BASH_STRING_LEN		0x100


/* Report #30, set to 1 to explore traffic in hexadecimal view, keep as 0 in rest cases */
#define R30_DUMPING	0

/* Marker of command to open site */
#define OPEN_SITE	"open"

/* Marker of command to pass authentication */
#define AUTH		"auth"

/* Marker of command to switch to tab 1, same as passing authentication, see <auth>  */
#define TAB1		"tab1"

/* Marker of command to switch to tab 2 */
#define TAB2		"tab2"

/* Marker of command to switch to tab 3 */
#define TAB3		"tab3"


/* Default RSA key; used when it's impossible to compute the one in conventional way */
#define STUB0 "286d0d177bd567ba5db27bb709a0f041b9400dbc1961f47fff06f8cf10ea1325023fba8aa416049d9897d1dff49088f67347c825d495741563154d1b749466c939b1cf4bf7175d73e93554b359580c46be069e0c87d21a7d3fb356c7d39d8f3a2ea0507b5b21aefc08ad2ec9d39b4858845e0dfc44c5792ec66925772deb8d7c"

/* Spare 1; Not used by now */
#define STUB1 "626da1760f49737dbb3a60fee63ad025fee41e65e7fa2347e5e1aaa4e9e7a8644ed4df93881998e2707c1417d8caba93398875cf7e837cc14119b9779e86aace7ebc256e6e6817fa90cd58ee5ebe50de6810308ed39298d5c468713186adaebdbd186715f1612828ff39c082aaadeafd2817d65b73a39a99a7dc8b946d992c38"

/* Spare 2; Not used by now */
#define STUB2 "626da1760f49737dbb3a60fee63ad025fee41e65e7fa2347e5e1aaa4e9e7a8644ed4df93881998e2707c1417d8caba93398875cf7e837cc14119b9779e86aace7ebc256e6e6817fa90cd58ee5ebe50de6810308ed39298d5c468713186adaebdbd186715f1612828ff39c082aaadeafd2817d65b73a39a99a7dc8b946d992c38"


/* Default cookie; used when it's impossible to compute the one in conventional way */
#define CUKY0 "effbf71a985814ee44e1181771a8a5a8"

/* Spare 1; Not used by now */
#define CUKY1 "770605707cda9615628eb35650a1bb6f"

/* Spare 2; Not used by now */
#define CUKY2 "353bcc80989c36c52a20fd3d4674b9a1"



/* Get-Post pair; TODO: give a comment */
typedef struct _GP 
{
	/* 0 - GET, otherwise - POST; 666 - is not processed, the rest - are */
	int iGetPost;

	/* Contents */
	char * pcAddrStr;

} Gp , * pGp;

/* Responce pair; TODO; used in <iRecvClbk()> */
typedef struct _RespStruct
{
	char * cpResponce;

	size_t iSize;

} RespStruct, *pRespStruct;


/* By this sequence we "open" website, so the certain calbacks on SRV side get prepared */
Gp aOpenArray[] = {

     { 0, "http://192.168.0.1/" },
     { 0, "http://192.168.0.1/webpages/login.html" },
     { 0, "http://192.168.0.1/webpages/css/widget.css" },
     { 0, "http://192.168.0.1/webpages/themes/green/css/style.css" },
     { 0, "http://192.168.0.1/webpages/js/libs/jquery.min.js" },
     { 0, "http://192.168.0.1/webpages/js/libs/jquery.nicescroll.min.js" },
     { 0, "http://192.168.0.1/webpages/js/su/locale.js" },
     { 0, "http://192.168.0.1/webpages/js/libs/encrypt.js" },
     { 0, "http://192.168.0.1/webpages/js/su/su.js" },
     { 0, "http://192.168.0.1/webpages/js/su/data/proxy.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/widget.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/window/msg.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/form.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/combobox.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/textbox.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/password.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/checkbox.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/button.js" },
     { 0, "http://192.168.0.1/webpages/js/su/widget/form/status.js" },
#if defined(EXTRA_PRECISION)
     { 0, "http://192.168.0.1/webpages/themes/green/img/icons.png"},
#endif /* (EXTRA_PRECISION) */
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/locale?form=lang" },
     { 0, "http://192.168.0.1/webpages/app.manifest" },
     { 0, "http://192.168.0.1/webpages/locale/en_US/lan.js?_=1481111286804" },
     { 0, "http://192.168.0.1/webpages/locale/en_US/lan.css" },
     { 0, "http://192.168.0.1/webpages/locale/en_US/help.js?_=1481111286805" },
     { 0, "http://192.168.0.1/webpages/locale/language.js?_=1481111286806" },
     { 0, "http://192.168.0.1/webpages/js/libs/encrypt.js" },
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/locale?form=list" },
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=cloud_login" },
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=login" },
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=initial_login" },
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=check_factory_default" },
     { 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/domain_login?form=dlogin" },
#if defined(EXTRA_PRECISION)
     {0, "http://192.168.0.1/webpages/themes/green/img/icons2.png"},
#endif /* (EXTRA_PRECISION) */

     { 0, NULL }
};

/* A specific data for get some server's stuff we use as JavaScript-software source on client's side */
Gp aCodeExtruderArray[] = {

	/* To get RSA-computation JavaScript-code use following HTTP-request(s), after 'opening' the site */
	{ 0, "http://192.168.0.1/webpages/js/libs/encrypt.js"},
	{ 0, NULL  }

};

/* Draft array. TODO: remove */
Gp _aAuthArray[] = {

	{ 2, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=login"},
//	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/locale?form=list"},
{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/ledgeneral?form=setting"},
//	{ 4/*3*/, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=settings"},

	{ 0x0, NULL }


};

/* TODO: give a comment */
Gp aAuthArray[]/* a.k.a. 'aTab1Array' */ = {

	{ 2, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=login"},
#if defined(EXTRA_PRECISION)
	{ 0, "http://192.168.0.1/webpages/themes/green/img/waiting.gif"},
#endif /* (EXTRA_PRECISION) */
	{ 0, "http://192.168.0.1/webpages/index.html"},
	{ 0, "http://192.168.0.1/webpages/css/widget.css"},
	{ 0, "http://192.168.0.1/webpages/js/libs/jquery.min.js"},
	{ 0, "http://192.168.0.1/webpages/themes/green/css/style.css"},
	{ 0, "http://192.168.0.1/webpages/js/libs/jquery.nicescroll.min.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/su.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/locale.js"},
	{ 0, "http://192.168.0.1/webpages/js/libs/encrypt.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/data/proxy.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/widget.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/msg.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/form.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/combobox.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/checkbox.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/textbox.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/button.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/password.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/status.js"},
	{ 0, "http://192.168.0.1/webpages/js/libs/jquery.scrollTo.min.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/data/store.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/data/treestore.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/panel.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/page.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/wizard.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/foldertree.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/keyword.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/grid/grid.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/grid/editor.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/grid/paging.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/fieldset.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/radio.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/textarea.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/time.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/file.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/timepicker.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/progressbar.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/slider.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/switch.js"},
	{ 666/*1000*/, "http://192.168.0.1/cgi-bin/luci/;stok=/locale?form=lang"},
#if defined(EXTRA_PRECISION)
	{ 0, "http://192.168.0.1/webpages/themes/green/img/loading.gif"},
	{ 0, "http://192.168.0.1/webpages/themes/green/img/icons2.png"},
	{ 0, "http://192.168.0.1/webpages/themes/green/img/icons.png"},
#endif /* (EXTRA_PRECISION) */
	{ 0, "http://192.168.0.1/webpages/locale/de_DE/lan.js?_=1482736660345"},
	{ 0, "http://192.168.0.1/webpages/locale/de_DE/lan.css"},
	{ 0, "http://192.168.0.1/webpages/locale/de_DE/help.js?_=1482736660346"},
	{ 0, "http://192.168.0.1/webpages/locale/language.js?_=1482736660347"},
	{ 1, "http://192.168.0.1/webpages/pages/userrpm/userFeedBack.html"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/locale?form=list"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/ledgeneral?form=setting"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/cloud_account?form=check_login"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/system?form=sysmode"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/cloud_account?form=check_support"},
	{ 0, "http://192.168.0.1/webpages/data/region.json?operation=read&_=1482736660348"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/feedback?form=content"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/cloud_account?form=check_cloud_version"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/cloud_account?form=check_upgrade"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/firmware?form=upgrade"},
	{ 1, "http://192.168.0.1/webpages/pages/frame/quick-setup.html"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/administration?form=account"},
	{ 0, "http://192.168.0.1/webpages/locale/ru_RU/ispAutoConf.js?_=1482736660349"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/locale?form=country"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/cloud_account?form=user_login"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/locale?form=country_list"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/quick_setup?form=timezone"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/network?form=status_ipv4"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/quick_setup?form=quick_setup"},

	{ 0x0, NULL }
};

/* TODO: give a comment */
Gp aTab2Array[] = {

	{ 1, "http://192.168.0.1/webpages/pages/frame/basic.html"},
	{ 0, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/menu?form=basic_menu"},
	{ 1, "http://192.168.0.1/webpages/pages/userrpm/basic_network.html"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/wireless?form=region"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/wireless?form=wireless_schedule_wifi_disable"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/status?form=all"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/status?form=internet"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/status?form=router"},
#if defined(EXTRA_PRECISION)
	{ 0, "http://192.168.0.1/webpages/themes/green/img/waiting.gif"},
#endif /* (EXTRA_PRECISION) */

	{ 0x0, NULL }
};


/* USB-Speichergeraet, selbst */
Gp aTab2Flash_Array[] = {

	{ 1, "http://192.168.0.1/webpages/pages/userrpm/basic_diskSetting.html"},
	{ 0, "http://192.168.0.1/webpages/js/libs/excanvas.js?_=1482829173051"},
	{ 0, "http://192.168.0.1/webpages/js/libs/Chart.js?_=1482829173052"},
	{ 1, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/disk_setting?form=metadata"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=settings"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=server"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=auth"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=partial"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=guest"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=media"},
	{ 1, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=volumn"},
	{ 1002, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/disk_setting?form=contents&serial=0320815020006996"},
	{ 1004, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=tree"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=mode"},
	{ 0x0, NULL }
};

/* USB-Flash Ausschalten */
Gp aTab2Flash_AUS_Array[] = {
	{ 4/*3*/, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=settings"},
	{ 0x0, NULL }
};

/* USB-Flash Einschalten */
Gp aTab2Flash_EIN_Array[] = {
	{ 204/*3*/, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/folder_sharing?form=settings"},
	{ 0x0, NULL } 
};

/* USB-Druecker, selbst */
Gp aTab2Printer_Array[] = {

	{ 1, "http://192.168.0.1/webpages/pages/userrpm/basic_print.html"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/print_server"},
	{ 0x0, NULL }
};

/* Druecker-Flash Ausschalten */
Gp aTab2Printer_AUS_Array[] = {
	{ 303, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/print_server"},
	{ 0x0, NULL }
};

/* Druecker-Flash Einschalten */
Gp aTab2Printer_EIN_Array[] = {

	{ 203, "http://192.168.0.1/cgi-bin/luci/;stok=52fa3b96ab31531111331f8e6e44fa88/admin/print_server"},
	{ 0x0, NULL }
};

Gp aTab3Array[] = {

	{ 1, "http://192.168.0.1/webpages/pages/frame/advanced.html"},
	{ 0, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/menu?form=advanced_menu"},
	{ 1, "http://192.168.0.1/webpages/pages/userrpm/status.html"},
	{ 1, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/wireless?form=region"},  
	{ 1, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/wireless?form=wireless_schedule_wifi_disable"},  
	{ 1, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/status?form=all"},
	{ 1, "http://192.168.0.1/cgi-bin/luci/;stok=6c2a1ef44697a73379a350deec6601a0/admin/status?form=internet"},  

	{ 0x0, NULL }
};


/* TODO: schreibt Kommentar */
Gp aExitArray[] = {

	{ 1006, "http://192.168.0.1/cgi-bin/luci/;stok=b2c63d5a14d0699b233094bae241cc89/admin/system?form=logout"},
	{ 0, "http://192.168.0.1/"},
	{ 0, "http://192.168.0.1/webpages/login.html"},
	{ 0, "http://192.168.0.1/webpages/css/widget.css"},
	{ 0, "http://192.168.0.1/webpages/themes/green/css/style.css"},
	{ 0, "http://192.168.0.1/webpages/js/libs/jquery.nicescroll.min.js"},
	{ 0, "http://192.168.0.1/webpages/js/libs/jquery.min.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/locale.js"},
	{ 0, "http://192.168.0.1/webpages/js/libs/encrypt.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/su.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/data/proxy.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/widget.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/window/msg.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/form.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/combobox.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/textbox.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/password.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/checkbox.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/button.js"},
	{ 0, "http://192.168.0.1/webpages/js/su/widget/form/status.js"},
#if defined(EXTRA_PRECISION)
	{ 0, "http://192.168.0.1/webpages/themes/green/img/icons.png"},
#endif /* (EXTRA_PRECISION) */
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/locale?form=lang"},
	{ 0, "http://192.168.0.1/webpages/locale/de_DE/lan.js?_=1482885989441"},
	{ 0, "http://192.168.0.1/webpages/locale/de_DE/lan.css"},
	{ 0, "http://192.168.0.1/webpages/locale/de_DE/help.js?_=1482885989442"},
	{ 0, "http://192.168.0.1/webpages/locale/language.js?_=1482885989443"},
	{ 0, "http://192.168.0.1/webpages/js/libs/encrypt.js"},
#if 0
	/* TODO: normalerweise braucht man dies nicht */
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/locale?form=list"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=cloud_login"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=login"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=initial_login"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/login?form=check_factory_default"},
	{ 1000, "http://192.168.0.1/cgi-bin/luci/;stok=/domain_login?form=dlogin"},
#endif /* (0) */

#if defined(EXTRA_PRECISION)
	{ 0, "http://192.168.0.1/webpages/themes/green/img/icons2.png"},
#endif /* (EXTRA_PRECISION) */
	{ 0x0, NULL }
};

#endif /* !defined(_SITE_CRAWLER_H_) */
