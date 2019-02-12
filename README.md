# libpam_upn2sam

Small module to in pam stack before libpam-krb5 to convert upn to sam account name.



# Work in progress

Install libpam-dev.

```bash
gcc -fPIC -fno-stack-protector -c src/main.c 

ld -x --shared -o /lib/x86_64-linux-gnu/security/pam_upn2sam.so main.o
```
## Example

in `/etc/pam.d/lightdm`

the auth part can be

```bash
auth  required      pam_upn2sam.so
auth  [success=2 default=ignore]  pam_krb5.so minimum_uid=1000
auth  [success=1 default=ignore]  pam_unix.so nullok_secure try_first_pass
auth  requisite     pam_deny.so
auth  required      pam_exec.so     /usr/local/sbin/create_dsa_user
auth  required      pam_permit.so
```

## Thanks

[fedetask](https://github.com/fedetask) for his 
[pam-tutorials](https://github.com/fedetask/pam-tutorials).


