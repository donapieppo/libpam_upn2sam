# libpam_upn2sam

Tiny module to add in pam stack before libpam-krb5 to convert upn to sam account name
(so to use realm instead of "email domain").

When the application (for example gdm3 / lightdm) gets the upn 
(user principal name) for the user, this pam module sets PAM_USER as
the corresponding sam account (good for kerberos authentication).

Note: actually the username part is copied and not converted asking a ldap server
the possible changes from upn to sam.

For example

name.surname@example.com -> name.surname@USER.EXAMPLE.COM

When called with 'reverse' keyword it converts the sam account name
to username

name.surname@USER.EXAMPLE.COM -> name.username

# Configuration

`/etc/libpam-upn2sam.conf` is the configuration file and contains 
the upn domains and the corresponding kerberos realms separated by `:`.

For example a file 

```bash
studio.example.com:STUDENTI.EXAMPLE.COM
example.com:EXAMPLE.COM
```

transforms the upn `name.surname@studio.example.com` in the sam accoun name
`name.surname@STUDENTI.EXAMPLE.COM` when the module il called with direct
param.

# INSTALLATION

To compile you need `libpam-dev` (and `libcurl4-openssl-dev` for webservice version).

Then:

```bash
gcc -fPIC -fno-stack-protector -c src/main.c 

ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_upn2sam.so main.o
```

or, for the version using a webservice:

```bash
gcc -fPIC -fno-stack-protector -c src/libpam_upn2sam_from_webservice.c 

ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_upn2sam_from_webservice.so libpam_upn2sam_from_webservice.o
```


## Example

in `/etc/pam.d/lightdm`

the auth part can be

```bash
auth  required      pam_upn2sam.so direct
auth  [success=2 default=ignore]  pam_krb5.so minimum_uid=1000
auth  [success=1 default=ignore]  pam_unix.so nullok_secure try_first_pass
auth  requisite     pam_deny.so
auth  required      pam_upn2sam.so reverse
auth  required      pam_exec.so     /usr/local/sbin/create_dsa_user
auth  required      pam_permit.so
```

## Thanks

Thanks to 
[fedetask](https://github.com/fedetask) for his nice 
[pam-tutorials](https://github.com/fedetask/pam-tutorials).


