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

/* TODO: give a comment */
#include <stdio.h>

/* TODO: give a comment */
#include <stdlib.h>

/* TODO: give a comment */
#include <string.h>

/* unlink() */
#include <unistd.h>

/* CURL library API */
#include <curl/curl.h>

/* Own interface, structures, definitions */
#include "site_crawler.h"




/* TODO: give a comment */
char cR30Token[R30_TKN_LENGTH+1];

char cR30Token_Wrapped[R30_TKN_LENGTH+5];//TODO: fix

/* Tocken is 32-char long string computed on side of P5 and passed to us in responce to TODO request */
static int m_TockenFound;



/* TODO: give a comment */
char cR30Passwd[R30_PSW_LENGTH+1];

/* TODO: give a comment */
char cR30Passwd_Sp[R30_PSW_SP_LENGTH+1];

/* TODO: give a comment */
char cR30Passwd_Wrapped[R30_PSW_LENGTH+64];

/* Passowrd is first member of bi-string array, in respoince to TODO request */
static int m_PasswordFound;


/* TODO: give a comment */
char cR30Cookie[R30_CKY_LENGTH+1];

/* TODO: give a comment */
char cR30Cookie_Wrapped[R30_CKY_LENGTH+15];//TODO: fix

/* Tocken is 32-char long string computed on side of P5 and passed to us in responce to TODO request */
static int m_CookieFound;



/* 32K supposedly is enough to include _any HTML responce from T5; used in <iRecvClbk()> */
char cBuffer[0x400*32];

/* Buffer to keep this session RSA key */
char STUB[R30_RSA_LEN + 1];




/* Dump cpontents of HTTP traffic being received; for usage on narrow consoles */
static void Dump(const char *text, FILE *stream, unsigned char *ptr, size_t size)
{
size_t i,  c;

unsigned int width=0x20;

#if (EXTRA_INFORMATIVITY)

	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size, (long)size);

	for( i = 0; i < size; i += width )
	{
		fprintf(stream, "%4.4lx: ", (long)i);

		/* Show hex to the left */
		for(c = 0; c < width; c++)
		{
			if(i+c < size)

				fprintf(stream, "%02x ", ptr[i+c]);
			/* else
				fputs(" ", stream); */
		}

		/* Last row reqiures special tabulation */
		if (i + width > size)

			for(c = 0; c < width - (size % width); c++)	

				fputs("   ", stream);

		/* Show data on the right */
		for(c = 0; (c < width) && (i+c < size); c++)

			fputc((ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.', stream);

		fputc('\n', stream);
	}
#endif /* (EXTRA_INFORMATIVITY) */

} /* static void Dump( . . ) */

/* Define 1 to not check HEX output profoundly */
#define SKIP_ONE_HEX 1

/* Dump cpontents of HTTP traffic being received; for usage on wide consoles */
static void WideDump(const char *text, FILE *stream, unsigned char *ptr, size_t size)
{
size_t i,  c;

unsigned int width=0x40;

#if (EXTRA_INFORMATIVITY)

	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size, (long)size);

	for( i = 0; i < size; i += width )
	{
		fprintf(stream, "%4.4lx: ", (long)i);

		/* Show hex to the left */
		for(c = 0; c < width; c++)
		{
#if (SKIP_ONE_HEX)
			if(i+c < size)
				if ( (i+c) % 2) 

					/* Output hex for even bytes only - screen is not enough */
					fprintf(stream, "%02x", ptr[i+c]);
				else
					/* And skip odd bytes, anyway nobody looks at them */
					fprintf(stream, " ");


#else
			/* Output hex'es w/o whitespace  */
			if(i+c < size)

				fprintf(stream, "%02x", ptr[i+c]);
#endif /* (SKIP_ONE_HEX) */

		}

#if (SKIP_ONE_HEX)
		/* Last row reqiures special tabulation */
		if (i + width > size)
		{

			for(c = 0; c < width - (size % width); c++)	
				if ( c % 2) 
					fputs("  ", stream);
				else
					fputs(" ", stream);

				if ( c % 2) fprintf(stream, " ");

		}

#else
		/* Last row reqiures special tabulation */
		if (i + width > size)

			for(c = 0; c < width - (size % width); c++)	

				fputs("  ", stream);
#endif /* (SKIP_ONE_HEX) */


		fprintf(stream, "   ");

		/* Show data on the right */
		for(c = 0; (c < width) && (i+c < size); c++)

			fputc((ptr[i+c]>=0x20) && (ptr[i+c]<0x80)?ptr[i+c]:'.', stream);

		fputc('\n', stream);
	}
#endif /* (EXTRA_INFORMATIVITY) */

} /* static void WideDump( . . . ) */


/* TODO: give a comment */
static int iGetTocken(unsigned char *ptr)
{
char * cpAjaxPtr, * cp1;

	/* Clear token (itself and wrapped one) contents, i.e. body + TR0 */
	memset (cR30Token, 0 , R30_TKN_LENGTH + 1);
	memset (cR30Token_Wrapped, 0 , R30_TKN_LENGTH + R30_TKN_WRP_LENGTH + 1);

	/* Clean token-found value for accuracy. We expect it also to be cleared in main() */
	m_TockenFound = 0;

	if ( NULL != ( cpAjaxPtr = strstr(ptr, "stok\":\"") ) )
	{
		cpAjaxPtr = & cpAjaxPtr [strlen ("stok\":\"") ];

		cp1 = strtok(cpAjaxPtr, "\"");

		if (R30_TKN_LENGTH == strlen (cp1) )
		{
			m_TockenFound = 1;

			/* Without TR0 - see first instr. of this fn. */
			memcpy(cR30Token, cp1, R30_TKN_LENGTH );

			memcpy(cR30Token_Wrapped, "stok=", R30_TKN_WRP_LENGTH);

			/* Without TR0 - see second instr. of this fn. */
			memcpy(&cR30Token_Wrapped[R30_TKN_WRP_LENGTH], cp1, R30_TKN_LENGTH);

			char cFileBuf[BASH_STRING_LEN];

			sprintf(cFileBuf,  "echo \"tocken: %s, wrapped tocken: %s\">> ./%s", cR30Token, cR30Token_Wrapped, TOKEN_FNAME);
			system (cFileBuf);

			return R30_SUCCESS;
		}
	}

	return R30_FAILURE;

} /* static int iGetTocken( . . .) */

/* TODO: give a comment */
static int iGetCookie(unsigned char *ptr, CURL * urlLib)
{
char * cpAjaxPtr, * cp1;

/* For exit with failure. But what if we don't need LUA-part of the site to work, i.e. what is we need only JS-part of it? */
int iRes;

	/* Clear cookie contents, i.e. body + TR0 */
	memset (cR30Cookie_Wrapped, 0 , R30_CKY_LENGTH + R30_WRP_CKY_LENGTH + 1 /* with TR0 */);

	/* Clean cookie-found value*/
	m_CookieFound = 0;

	if ( NULL != ( cpAjaxPtr = strstr(ptr, "sysauth=") ) )
	{
		memcpy(cR30Cookie_Wrapped, cpAjaxPtr, R30_CKY_LENGTH + R30_WRP_CKY_LENGTH /* without TR0 */);


#if (DONT_REFRESH_COOKIES)
		/* Let's stop for new cookies throughout working session; why not? */
		m_CookieFound = 1;
#endif /* (0) */

		iRes = curl_easy_setopt(urlLib, CURLOPT_COOKIE, cR30Cookie_Wrapped);

		char cFileBuf[BASH_STRING_LEN];		

		sprintf(cFileBuf,  "echo \"Wrapped cookie: %s\">> ./%s", cR30Cookie_Wrapped, CKY_FNAME);
		system (cFileBuf);

		return R30_SUCCESS;
	}

	return R30_FAILURE;

} /* static int iGetCookie(. . . ) */



/* TODO: give a comment */
static int iGetPassword(unsigned char *ptr)
{
char * cpAjaxPtr, * cpAjaxPtr_Sp;

char * cp1;

	/* Clear password contents */
	memset (cR30Passwd, 0 , R30_PSW_LENGTH);

	/* Clear password-sp's contents */
	memset (cR30Passwd_Sp, 0 , R30_PSW_SP_LENGTH);
	
	/* Clean password-found value for accuracy. We expect it also to be cleaned in main() */
	m_PasswordFound = 0;

	if ( NULL != ( cpAjaxPtr_Sp = cpAjaxPtr = strstr(ptr, "password\":[ \"") ) )
	{
		cpAjaxPtr = & cpAjaxPtr [strlen ("password\":[ \"") ];

		cpAjaxPtr_Sp = & cpAjaxPtr_Sp [strlen ("password\":[ \"")  + R30_PSW_LENGTH + 4 /* strlen(", ") */ ];

		memcpy (cR30Passwd_Sp, cpAjaxPtr_Sp, R30_PSW_SP_LENGTH); 

		cp1 = strtok(cpAjaxPtr, "\"");

		if (R30_PSW_LENGTH == strlen (cp1) )
		{
			m_PasswordFound = 1;

			memcpy(cR30Passwd, cp1, R30_PSW_LENGTH+1 );

			char cFileBuf[BASH_STRING_LEN*8];		

			sprintf(cFileBuf,  "echo \"password: %s, special: %s\">> ./%s", cR30Passwd, cR30Passwd_Sp, PASSWD_FNAME);
			system (cFileBuf);

			return R30_SUCCESS;
		}
	}

	return R30_FAILURE;

} /* static int iGetPassword( . . . ) */


/* Callback to execute on arrival of HTML responce */
static int iTrace(CURL * handle, curl_infotype type, char *data, size_t size, void *userp)
{
const char *text;

(void)handle;

#if (EXTRA_INFORMATIVITY)

	switch (type)
	{
		/* In case a new one is introduced to knock me out */
		default:
		case CURLINFO_TEXT:
		{
			/* Self-explanatory:printf("[%s] %s: Skipping 'Info' or unknown header\n", __FILE__, __func__);*/
			return R30_FAILURE;
		}

		case CURLINFO_HEADER_OUT:
			text = "=> Send header";
		break;

		case CURLINFO_DATA_OUT:
			text = "=> Send data";
		break;

		case CURLINFO_SSL_DATA_OUT:
			text = "=> Send SSL data";
		break;

		case CURLINFO_HEADER_IN:
			text = "<= Recv header";
		break;

		case CURLINFO_DATA_IN:
			text = "<= Recv data";
		break;

		case CURLINFO_SSL_DATA_IN:
			text = "<= Recv SSL data";
		break;
	}

#if (0)
	Dump(text, stderr, (unsigned char *)data, size);
#else
	WideDump(text, stderr, (unsigned char *)data, size);
#endif /* (0) */


#endif /* (EXTRA_INFORMATIVITY) */

	/* Look for password only in data section of incomming packets */
	if (0 ==  m_PasswordFound && CURLINFO_DATA_IN == type)

			iGetPassword((unsigned char *)data );

	/* Look for tockens only in data section of incomming packets */
	if (0 ==  m_TockenFound && CURLINFO_DATA_IN == type)

			iGetTocken((unsigned char *)data );

	/* Look for cookies only in header section of outgoing packets */
	if (0 ==  m_CookieFound  && CURLINFO_HEADER_IN == type )

			iGetCookie((unsigned char *)data , handle);

	return R30_SUCCESS;

} /* static int iTrace( . . . ) */

static int iProcessArray(CURL * curl, void * pGpArray)
{
int i=0;

CURLcode iRes;

/* Pointer to an array being used currently */
pGp pGP_Array;

	pGP_Array = (pGp)pGpArray;

	while ( NULL != pGP_Array[i].pcAddrStr )
	{
#if (EXTRA_INFORMATIVITY)

		//.printf("%d : \t %d \t  %s  \n", i, pGP_Array[i].iGetPost , pGP_Array[i].pcAddrStr ) ;

#endif /* (EXTRA_INFORMATIVITY) */

		/* Temporary buffer to compose a XML payload of POST request */
		char cTemporary[0x400];

		/* Make variable instad of static-initialized, so the strstr() works on it */
		char pGP_ArrayI_pcAddrStr[R30_HTTP_LENGTH];

		strcpy (pGP_ArrayI_pcAddrStr, pGP_Array[i].pcAddrStr);

		/* <m_TockenFound> in perticular means that <cR30Token_Wrapped> is not NULL */
		if (m_TockenFound) 
		{
		char * pcHayStack = NULL;

			//strcpy (pGP_ArrayI_pcAddrStr, pGP_Array[i].pcAddrStr);

			if (NULL != (pcHayStack = strstr(pGP_ArrayI_pcAddrStr, "stok=")   ))
			{
				strcpy (pGP_ArrayI_pcAddrStr, pGP_Array[i].pcAddrStr);

				/* for all except very first and very specific inhabitor of <stok> */
				if (  2 != pGP_Array[i].iGetPost  )

					memcpy( pcHayStack , cR30Token_Wrapped , R30_TKN_LENGTH+R30_TKN_WRP_LENGTH);//TODO: fix; no TR0
			}


		}

		/* From now on let's work with <pGP_ArrayI_pcAddrStr> insted of <pGP_Array[i].pcAddrStr> */

		/* GET operations, no payload */
		if (0 == pGP_Array[i].iGetPost )
		{
			curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);

			iRes = curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr );
		}

		/* No payload POST operations */
		else if ( 1 == pGP_Array[i].iGetPost ) 
		{
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, 0/* "" cTemporary */);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0 /* (long)strlen(cTemporary)*/ );

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}
		/* Operation == login, payload ist must */
		else if (2 == pGP_Array[i].iGetPost )
		{
			/* We don't need no needle to be giving us a thrill */
			sprintf (cTemporary, "operation=login&password=%s", STUB0);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr );
		}


		/* Operation == read, vorbereiten */
		else if (1000 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=read");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		/* Operation == load, vorbereiten */
		else if (1002 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=load");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		/* Operation == load&path, vorbereiten */
		else if (1004 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=load&path=&uuid=06E7656ECAADDAAD31E883C869D713702e0F");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		/* Operation == write, vorbereiten */
		else if (1006 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=write");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		/* Operation == Druecker ausschalten */
		else if (303 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=write&enable=off");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		/* Operation == druecker einschalten */
		else if (203 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=write&enable=on");

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		/* Operation == Flashspeicher ausschalten */
		else if (4 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=save&server=TPShare&enable=off%s2Coff%s2Coff%s2Coff&port=21", "%", "%", "%" );

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);


		}
		/* Operation == Flashspeicher ausschalten */
		else if (204 == pGP_Array[i].iGetPost )
		{
			sprintf (cTemporary, "operation=save&server=TPShare&enable=off%s2Coff%s2Coff%s2Con&port=21", "%", "%", "%" );

			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cTemporary);

			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(cTemporary));

			curl_easy_setopt(curl, CURLOPT_URL, pGP_ArrayI_pcAddrStr);
		}

		iRes = curl_easy_perform(curl);

		i++;
	}

	return iRes;

} /* int iProcessArray(.  .  . )  */


static size_t iRecvClbk(void *contents, size_t size, size_t nmemb, void *userp)
{
size_t realsize = size * nmemb;

RespStruct * HtmlRespStruct = (RespStruct *)userp;

	HtmlRespStruct->cpResponce = (char*)(cBuffer);

	memcpy(HtmlRespStruct->cpResponce, contents, realsize);

	HtmlRespStruct->cpResponce[realsize] = 0;

	HtmlRespStruct->iSize = realsize;

	return realsize;

} /* size_t iRecvClbk( . . . )  */

static void ComputeRSA()
{ 
char cNodeBuf[BASH_STRING_LEN], cRsaBuf[R30_RSA_LEN+1];

FILE * rsaFile;

	// No worries, but be sure you've done <apt-get install node> <apt-get install nodejs> first
	sprintf(cNodeBuf,  "%s ./%s >%s", INTERPRETER_FNAME, RSA_COMPUTER_FNAME, ENCR_FNAME);

	system (cNodeBuf);

	rsaFile = fopen(ENCR_FNAME, "r");

	if (NULL != rsaFile)
	{

		fflush(rsaFile);

		fscanf(rsaFile, "%s", cRsaBuf);

		fclose(rsaFile);
	}
	else
	{
		; /* do noting, we still may work wit pre-computed RSAs */
	}

	if (R30_RSA_LEN == strlen(cRsaBuf)  )

		/* Use freshest (valid) value */
		strcpy(STUB, cRsaBuf);
	else
		/* Use one of pre-computed values (they may appear to be not valid) */
		strcpy(STUB, STUB0);

} /* static void ComputeRSA( ) */


int main (int argc, char **argv)
{
CURL *urlLib;

CURLcode iRes;

char cOpCode[R30_STRNLEN];

	/* True or forged, we need it for unlocking the site */
	ComputeRSA();

	/* Initialize variables and callbacks of library */
	urlLib = curl_easy_init();

	/* TODO: add comment */
	if(urlLib)
	{
	char cTemporary[0x200];

		iRes = curl_easy_setopt(urlLib, CURLOPT_DEBUGFUNCTION, iTrace );		
		iRes = curl_easy_setopt(urlLib, CURLOPT_HEADER, 1L);

		/* So far I experienced there's no other lets use this one. TODO: check if it's really so in <P5> code*/
		iRes = curl_easy_setopt(urlLib, CURLOPT_REFERER, "http://192.168.0.1/webpages/index.html");
		
		/* Assign default value with which LUA-part of the site won't work anyway; only JS-part will. */
		sprintf (cTemporary, "sysauth=%s", CUKY0);
		iRes = curl_easy_setopt(urlLib, CURLOPT_COOKIE, cTemporary);

		/* Put our designations into traffic, so we're able to distingiosh own cookies from the rest */
		sprintf (cTemporary, "Mozilla/5.0 (X11; Ubuntu; %s) %s", argv[0], R30_CKY_MARKER);
		iRes = curl_easy_setopt(urlLib, CURLOPT_USERAGENT, cTemporary);

		iRes = curl_easy_setopt(urlLib, CURLOPT_CONNECTTIMEOUT, 30 );		
		iRes = curl_easy_setopt(urlLib, CURLOPT_VERBOSE, 1L);


		/* Num of test repetitions*/
		int iRepetitions = 1;
		
		/* Let's open site */
		while (iRepetitions--)  {

		/* TODO: deploy for checking, or move away otherwise */
		int iRes;

			/* We should compute them anew each time we're opening the site */
			m_PasswordFound = m_TockenFound = m_CookieFound = 0;

			/* Let's open site. Mandatory for any other operation to be effective */
			iRes = iProcessArray(urlLib, (void *) aOpenArray);

			/* Let's sleep for a site to become stable */
			sleep (R30_GP_TMO);

			/* Here we have a change that <m_TockenFound> becomes 1 */
	
			/* Let's open first tab of site. Alegedly mandatory for any other operation to be effective */
			iRes = iProcessArray(urlLib, (void *) aAuthArray);

			/* Self-explanatory */
			printf("[%s] %s Site unlocked [%d]. Now can do _any operations\n", __FILE__, __func__, iRepetitions);

			/* Let's sleep for a site to become stable */
			sleep (R30_GP_TMO);

			/* Transit to second tab of site - place where the flash and print-server dwell */
			iRes = iProcessArray(urlLib, (void *) aTab2Array);

			/* Let's sleep for a site to become stable */
			sleep (R30_GP_TMO);

			/* Transit to second tab of site - place where the flash and print-server dwell */
			iRes = iProcessArray(urlLib, (void *) aTab2Array);

			/* Let's sleep for a site to become stable */
			sleep (R30_GP_TMO);




			/* Open the flash applet */
			iRes = iProcessArray(urlLib, (void *) aTab2Array);

			/* Let's sleep for a site to become stable */
			sleep (R30_GP_TMO);

			/* Switch off the flash */
			iRes = iProcessArray(urlLib, (void *) aTab2Flash_AUS_Array);

			/* Wait for a board to execute the <sftp_srv stop + PARAM_SAVE>, being invoced by LUA */
			sleep (R30_GP_TMO);

			/* Switch on the flash */
			iRes = iProcessArray(urlLib, (void *) aTab2Flash_EIN_Array);

			/* Wait for a board to execute the <sftp_srv start + PARAM_SAVE>, being invoced by LUA */
			sleep (R30_GP_TMO);

			/* Self-explanatory */
			printf("[%s] %s Flash tested [%d]\n", __FILE__, __func__ , iRepetitions);





			/* Open the printer applet */
			iRes = iProcessArray(urlLib, (void *) aTab2Printer_Array);

			/* Let's sleep for a site to become stable */
			sleep (R30_GP_TMO);

			/* Switch off the printer */
			iRes = iProcessArray(urlLib, (void *) aTab2Printer_AUS_Array);

			/* Wait for a to unload printer drivers, being invoced by LUA */
			sleep (R30_GP_TMO);

			/* Switch on the printer */
			iRes = iProcessArray(urlLib, (void *) aTab2Printer_EIN_Array);

			/* Wait for a to load printer drivers and bring-up Net interfaces, being invoced by LUA */
			sleep (R30_GP_TMO);

			/* Self-explanatory */
			printf("[%s] %s Printer tested [%d]\n", __FILE__, __func__ , iRepetitions);



			
			/* Leave the site; let's not leave an opened backdoor after us. */
			iRes = iProcessArray(urlLib, (void *) aExitArray);

			/* Self-explanatory */
			printf("[%s] %s Site closed[%d]. No opetaion is allowed unless it's opened again next time\n", __FILE__, __func__ , iRepetitions);
		}

		/* Clean after ourselves */
		curl_easy_cleanup(urlLib);

	} /* if(urlLib) */

#if (EXTRA_PURITY)
	unlink (ENCR_FNAME);

	unlink (CKY_FNAME);

	unlink (TOKEN_FNAME);

	unlink (PASSWD_FNAME);
#endif /* (EXTRA_PURITY) */

	/* TODO: who will catch this return code. if noone then what's the point? */
	return R30_SUCCESS;

} /* int main (int argc, char **argv) */
