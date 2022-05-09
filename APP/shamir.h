#ifndef __SHAMIR_H__
#define __SHAMIR_H__

#define SHAMIR_PART_LEN(l)	(2*sizeof(unsigned int)+2*(l))

/// Seed the random number generator.  MUST BE CALLED before using the library (unless on arc4random() system).
void seed_random(void);

int shamir_get_sharelen(int secret_len);
int shamir_recovery_sharelen(unsigned char *one_share);
int shamir_split(unsigned char *secret, int len, int share_number, int share_threshold, unsigned char **shares);
int shamir_combine(unsigned char **shares, int share_count, unsigned char *secret, int *secret_len);

#endif
