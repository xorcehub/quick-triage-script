
#include <stdio.h>
static const char *paths[] = {
    "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    "AppData\\Roaming\\discord\\Local Storage\\leveldb",
    "AppData\\Roaming\\telegram\\tdata",
    "wallet.dat", "metamask", "electrum", "keystore.pma",
};
int main(void) { for (int i = 0; i < 7; i++) puts(paths[i]); return 0; }
