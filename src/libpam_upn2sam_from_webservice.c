#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <time.h>
#include <stdbool.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#define BIG_ENOUGH 200 /* string lenght of domains */
#define MAX_DOMAINS 10 /* max number of different domains */

struct ResponseStruct {
  char *memory;
  size_t size;
};

/* size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
 * https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 * contents = Raw buffer from libcurl
 * size     = number of indices
 * nmemb    = size of each index
 * userp    = any extra user data needed */
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct ResponseStruct *mem = (struct ResponseStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

/* example getArg('url', argc, argv) */
static const char* getArg(const char* pName, int argc, const char** argv) {
	int len = strlen(pName);
	int i;

	for (i = 0; i < argc; i++) {
		if (strncmp(pName, argv[i], len) == 0 && argv[i][len] == '=') {
			// only give the part url part (after the equals sign)
			return argv[i] + len + 1;
		}
	}
	return 0;
}


/* Get the username part */
/* upn2username("p.q@studio.unibo.it", res) */
/* res = 'p.q' */
void upn2username(const char *upn, char *username) {
	for (int i=0; i<BIG_ENOUGH; i++) {
		if (upn[i] == '@') {
			username[i] = '\0';
			break;
		}
		username[i] = upn[i];
	}
}


static int upn2sam(const char *webserviceUrl, const char *upn, char *sam) {
  /* web service to call with param upn 
     http://st-deposito1.virtlab.unibo.it:3000/pam_create?upn=pietro.donatini@unibo.it */
  char url[256];
  snprintf(url, sizeof url, "%s?upn=%s", webserviceUrl, upn);
  syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam web service url=%s\n", url);

  CURL *curl;
  CURLcode res;

  struct ResponseStruct chunk;
  
  chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
  chunk.size = 0;           /* no data at this point */

  curl_global_init(CURL_GLOBAL_ALL);

  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

  /* get it! */
  res = curl_easy_perform(curl);

  /* check for errors */
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }
  else {
    syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam web: result=%s\n", chunk.memory);
    strncpy(sam, chunk.memory, BIG_ENOUGH);
  }

  /* cleanup curl stuff */
  curl_easy_cleanup(curl);

  free(chunk.memory);

  /* we're done with libcurl, so clean it up */
  curl_global_cleanup();

  return 0;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv) {
	int pam_code;
	const char *provided_pam_user = NULL;
	char new_pam_user[BIG_ENOUGH];
  const char* webserviceUrl = NULL;
  const char* method = NULL;

  /* GET provided_pam_user */
	setlogmask (LOG_UPTO (LOG_DEBUG));
	pam_code = pam_get_user(handle, &provided_pam_user, "USERNAME: ");

	if (pam_code != PAM_SUCCESS) {
		syslog(LOG_AUTH, "Can't get provided_pam_user");
		return PAM_PERM_DENIED;
	} else {
		syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam: pam_get_user = PAM_SUCCESS for provided_pam_user=%s\n", provided_pam_user);
	}

  method = getArg("url", argc, argv);
	if (!method) {
		return PAM_AUTH_ERR;
	}

  webserviceUrl = getArg("url", argc, argv);
	if (!webserviceUrl) {
		return PAM_AUTH_ERR;
	}

  syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam called with method=%s and  url=%s", method, webserviceUrl);

	if (strcmp(method, "direct") == 0) {
		syslog(LOG_DEBUG, "pam upn2sam in direct mode upn2sam");
		upn2sam(webserviceUrl, provided_pam_user, new_pam_user);
	} else {
		syslog(LOG_DEBUG, "pam upn2sam in reverse model upn2username");
		upn2username(provided_pam_user, new_pam_user);
	}
	syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam has got new_pam_user=%s\n", new_pam_user);
	pam_set_item(handle, PAM_USER, new_pam_user);

	return PAM_SUCCESS;
}


/* int pam_get_user(pamh, user, prompt); */	 
/* const pam_handle_t *pamh; */
/* const char **user; */
