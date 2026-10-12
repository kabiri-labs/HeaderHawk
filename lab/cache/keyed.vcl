vcl 4.1;

# The same cache with the hole closed: a header the back-end honours belongs
# in the key. The poisoned copy is then filed under its own key and a request
# that never carried the header gets the clean one.
#
# The application still honours the header, so HeaderHawk is expected to say
# so - and expected not to call it poisoning, because nothing was served to
# anyone who did not ask for it.

backend default {
    .host = "app";
    .port = "8000";
}

sub vcl_hash {
    if (req.http.X-Forwarded-Host) {
        hash_data(req.http.X-Forwarded-Host);
    }
}
