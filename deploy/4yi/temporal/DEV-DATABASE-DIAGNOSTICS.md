# Temporary development database diagnostics

Startup always logs the selected PostgreSQL host, port, role, bootstrap database,
password presence, and login success/failure. It never dumps the full environment.

For the user-authorized development investigation only, set
`SHANNON_DEBUG_DATABASE_CREDENTIALS=true` on the Temporal container and restart it
using the updated Temporal image. This additionally prints the **current configured
password in plaintext** at process startup (including each container restart).
The declaration does not enable this flag for other installations. Platform log
redaction may still hide it. Do not paste the plaintext log into public reports.

PostgreSQL stores a password verifier, not retrievable plaintext. A successful
login with the configured role/password proves it is accepted by the reached
server; authentication failure does not reveal the original database password.
Check the selected host and role as well as the supplied credential.

After diagnosis, unset the flag or set it to `false`, restart Temporal, rotate any
credential exposed to logs with a coordinated database-role and Secret update,
and remove the temporary plaintext branch and its tests from this repository.
Removing the flag does not remove historical logs. Preserve the PVC throughout.
