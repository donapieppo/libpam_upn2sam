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

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

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

  upn2username(upn, username);

  if (strstr(upn, "@studio.unibo.it")) {
    snprintf(sam, 200, "%s@STUDENTI.DIR.UNIBO.IT\0", username);
  } else if (strstr(upn, "@unibo.it")) {
    snprintf(sam, 200, "%s@PERSONALE.DIR.UNIBO.IT\0", username);
  } else {
    strcpy(sam, upn);
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

	pam_code = pam_get_user(handle, &upn, "USERNAME: ");

	if (pam_code != PAM_SUCCESS) {
		fprintf(stderr, "Can't get upn\n");
		return PAM_PERM_DENIED;
	} else {
		fprintf(stderr, "pam dsa has got upn=%s\n", upn);
	}

	syslog(LOG_AUTH|LOG_DEBUG, "pam dsa has got upn=%s\n", upn);

	upn2sam(upn, sam);
	pam_set_item(handle, PAM_USER, sam);

	return PAM_SUCCESS;
}


