vcl 4.1;

# A cache with nothing but a backend: the default key is the method, the host
# and the URL. X-Forwarded-Host is not in it, and the application behind this
# builds its links from X-Forwarded-Host. That pair is the cache-poisoning
# gadget, and it needs no custom VCL to exist - which is the point worth
# making. This is what a default deployment does.

backend default {
    .host = "app";
    .port = "8000";
}
