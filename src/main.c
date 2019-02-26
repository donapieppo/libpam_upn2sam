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

/* after parsing 
 * domain_from[i] = 'pippo.com' 
 * domain_to[i]   = 'PIPPO.DOMAIN.COM'
 * returns the number of domains read from conf (<MAX_DOMAINS)
 */
int parse_configuration(char domain_from[MAX_DOMAINS][BIG_ENOUGH], char domain_to[MAX_DOMAINS][BIG_ENOUGH]) {
	FILE * fp;

	int  domain_number = 0;

	char ch;
	int  ch_number = 0;
	char *buf;

	if ((fp = fopen(CONFFILE, "r")) == NULL) {	
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

	syslog(LOG_DEBUG, "pam upn2sam read %d domains from conf file.\n", domain_number);
	for (int i=0; i<domain_number; i++) {
		syslog(LOG_DEBUG, "pam upn2sam read domain_from=%s -> domain_to=%s\n", domain_from[i], domain_to[i]);
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

	int domains_count = parse_configuration(domain_from, domain_to);

	/* extract username from upn (upn=pippo.pluto@example.com username=pippo.pluto) */
	upn2username(upn, username);

	/* copy for default (in case of no domanin found) */
	strncpy(sam, upn, BIG_ENOUGH);

	/* search for domain in upn and change */
	for (int i=0; i<domains_count; i++) {
		/* strstr('name.surname@example.com', 'example.com') */
		/* first find, put smaller realms after long realms in config :-) */
		if (strstr(upn, domain_from[i])) {
			snprintf(sam, 200, "%s@%s\0", username, domain_to[i]);
			break;
		} 
	}
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv) {
	int pam_code;
	const char *provided_pam_user = NULL;
	char new_pam_user[200];

	setlogmask (LOG_UPTO (LOG_DEBUG));
	pam_code = pam_get_user(handle, &provided_pam_user, "USERNAME: ");

	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get provided_pam_user\n");
		return PAM_PERM_DENIED;
	} else {
		fprintf(stderr, "pam upn2sam: pam_get_user = PAM_SUCCESS for provided_pam_user=%s\n", provided_pam_user);
	}

	syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam pam_get_user = PAM_SUCCESS for provided_pam_user=%s\n", provided_pam_user);

	if (argc == 1) {
		syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam called with argv=%s", argv[0]);

		if (strcmp(argv[0], "direct") == 0) {
			syslog(LOG_DEBUG, "pam upn2sam in direct mode upn2sam");
			upn2sam(provided_pam_user, new_pam_user);
			syslog(LOG_AUTH|LOG_DEBUG, "pam upn2sam has got new_pam_user=%s\n", new_pam_user);
		} else {
			syslog(LOG_DEBUG, "pam upn2sam in reverse model upn2username");
			upn2username(provided_pam_user, new_pam_user);
		}
		pam_set_item(handle, PAM_USER, new_pam_user);
	} else {
		syslog(LOG_AUTH, "pam upn2sam please provide direct or reverse param");
	}
	return PAM_SUCCESS;
}


