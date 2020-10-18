/* silent gcc */
int chroot(const char *);

int chroot(const char *path)
{
    (void)path;
    return 0;
}
