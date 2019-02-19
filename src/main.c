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

#define CONFFILE "/etc/libpam-upn2sam.conf"
#define BIG_ENOUGH 200 /* string lenght of domains */
#define MAX_DOMAINS 10 /* max number of different domains */

int parse_configuration(char domain_from[MAX_DOMAINS][BIG_ENOUGH], char domain_to[MAX_DOMAINS][BIG_ENOUGH]) {
  FILE * fp;

  int  domain_number = 0 ;

  char ch;
  int  ch_number = 0;
  char *buf;

  fp = fopen(CONFFILE,"r");

  if (fp == NULL) {
    perror("Error while opening the file.\n");
    return(0);
  }

  buf = domain_from[domain_number];

  while((ch = fgetc(fp)) != EOF) {
    if (ch_number ++ > BIG_ENOUGH) {
      perror("Configuration file with too long lines.\n");
      return(0);
    }
    if (ch == ':') {
      /* end of domain_from, start with domain_to */
      *buf = '\0';
      buf = domain_to[domain_number];
    } else if (ch == '\n') {
      /* end of domain_to, restart with domain_from */
      *buf = '\0';
      if (domain_number++ > MAX_DOMAINS) {
        perror("Too many domains.\n");
        return(domain_number - 1);
      }
      buf = domain_from[domain_number];
    } else {
      /* keep copying */
      *buf = ch;
      buf++;
    }
  }

  fclose(fp);

  syslog(LOG_DEBUG, "pam upn2sam has got %d domains\n", domain_number);
  for (int i=0; i<domain_number; i++) {
    syslog(LOG_DEBUG, "pam upn2sam has got domain_from=%s -> domain_to=%s\n", domain_from[i], domain_to[i]);
  }

  return(domain_number);
}

/* Get the username part */
/* upn2username("p.q@studio.unibo.it", res) */
/* res = 'p.q' */
void upn2username(const char *upn, char *username) {
  for (int i=0; i<200; i++) {
    if (upn[i] == '@') {
      username[i] = '\0';
      break;
    }
    username[i] = upn[i];
  }
}

void upn2sam(const char *upn, char *sam) {
  char username[200];

  char domain_from[MAX_DOMAINS][BIG_ENOUGH]; /* array of upn domains  */
  char domain_to[MAX_DOMAINS][BIG_ENOUGH];   /* array of sams domains */

  int domain_number = parse_configuration(domain_from, domain_to);

  /* extract username from upn (upn=pippo.pluto@example.com username=pippo.pluto) */
  upn2username(upn, username);

  /* copy for default (in case of no domanin found) */
  strcpy(sam, upn);

  /* search for domain in upn and change */
  for (int i=0; i<domain_number; i++) {
    if (strstr(upn, domain_from[i])) {
      snprintf(sam, 200, "%s@%s\0", username, domain_to[i]);
    } 
  }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
				   const char **argv)
{
	int pam_code;
	const char *upn = NULL;
	char sam[200];

	setlogmask (LOG_UPTO (LOG_DEBUG));
	pam_code = pam_get_user(handle, &upn, "USERNAME: ");

	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get upn\n");
		return PAM_PERM_DENIED;
	} else {
		fprintf(stderr, "pam upn2sam has got upn=%s\n", upn);
	}

	syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam has got upn=%s\n", upn);

	upn2sam(upn, sam);

	syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam has got sam=%s\n", sam);
	pam_set_item(handle, PAM_USER, sam);

	return PAM_SUCCESS;
}


