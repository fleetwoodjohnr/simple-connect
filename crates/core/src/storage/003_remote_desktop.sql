-- Remote desktop: the sign-in name (NULL = the SSH user), the preferred way to
-- open the desktop (NULL = choose automatically) and a reference to its saved
-- password in the credential store.
ALTER TABLE profiles ADD COLUMN rd_user TEXT;
ALTER TABLE profiles ADD COLUMN rd_method TEXT;
ALTER TABLE profiles ADD COLUMN rd_secret_ref TEXT;
