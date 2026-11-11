#!/usr/bin/env bash
#
# 39-nginx-modsecurity.sh
#
# Adds ModSecurity (OWASP Core Rule Set) as a WAF in front of every nginx
# vhost: the general website (e.g. example.com) and every grommunio vhost alike
# (webmail, admin-web/-api on 8080/8443, ActiveSync, DAV) - the admin's
# explicit choice (2026-10-12), over leaving the grommunio vhosts out.
#
# Debian's packages do almost all of the work:
#   - libnginx-mod-http-modsecurity ships the nginx module and already
#     symlinks it into /etc/nginx/modules-enabled/ on install (same pattern
#     as the brotli/vhost-traffic-status modules from 33-nginx-sites.sh), and
#     ships /etc/nginx/modsecurity.conf with SecRuleEngine set to
#     DetectionOnly (log, don't block) out of the box. This step's own
#     /etc/nginx/modsec/main.conf overrides that to `SecRuleEngine On`
#     (blocking) - see the comment next to that line for why. Findings
#     (blocked or, during the original tuning period, would-have-been-
#     blocked) land in /var/log/nginx/modsec_audit.log.
#   - modsecurity-crs ships the actual OWASP rules under
#     /usr/share/modsecurity-crs/rules/, including a ready-made Nextcloud
#     exclusion set (grommunio-files is Nextcloud-based) that should cut
#     down false positives there without us hand-tuning anything yet.
#
# modsecurity-crs's own load file (/usr/share/modsecurity-crs/owasp-crs.load,
# which libnginx-mod-http-modsecurity's /etc/nginx/modsecurity_includes.conf
# offers, commented out, as the CRS include) uses IncludeOptional - an
# Apache mod_security2-only directive. nginx's ModSecurity v3 connector
# does not understand it ("nginx -t": "Invalid input"), so this step writes
# its own /etc/nginx/modsec/main.conf with plain Include lines for the same
# files instead (they all exist - shipped by modsecurity-crs itself, so
# "optional" was never needed here). modsecurity_includes.conf itself is
# left untouched.
#
# modsecurity on + the rules file are set once, in the http{} block (via
# /etc/nginx/conf.d/, already included there by nginx.conf), so every vhost
# under it inherits it - no per-vhost edits needed.
#
# Confirmed live on testvps (2026-10-12, DetectionOnly, real phone traffic):
# every ActiveSync request (phone mail/contacts/calendar sync) matched CRS
# rule 920420 ("Request content type is not allowed by policy", for
# application/vnd.ms-sync.wbxml) and would have been blocked once
# SecRuleEngine is switched to On. This step adds a targeted exclusion for
# that one rule, scoped to the ActiveSync endpoint only, in
# /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf (the file
# modsecurity-crs itself designates for local exclusions).
#
# This step is safe to re-run: package install is a no-op if already done,
# the ActiveSync exclusion is only appended if not already present, and both
# /etc/nginx/modsec/main.conf and the conf.d file are only rewritten if
# their content differs from what is wanted.

step_nginx_modsecurity()
{
    require_root
    require_cmd nginx

    apt-get install -y libnginx-mod-http-modsecurity modsecurity-crs \
        || die "Could not install libnginx-mod-http-modsecurity/modsecurity-crs."

    # ActiveSync (phone mail/contacts/calendar sync) POSTs
    # application/vnd.ms-sync.wbxml, which is not in CRS's default allowed
    # request content-type list (rule 920420), pushing the anomaly score to
    # the default blocking threshold on every single sync request. Confirmed
    # live 2026-10-12 via modsec_audit.log while testing phone sync. Scoped
    # to just this endpoint and just this one rule, so the global
    # content-type policy is untouched everywhere else. This file is the
    # one modsecurity-crs itself designates for local exclusions.
    local excl="/etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
    backup_file "$excl"
    if [[ -f "$excl" ]] && ! grep -q 'id:9000001,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: ActiveSync (phone mail/contacts/calendar sync) POSTs
# application/vnd.ms-sync.wbxml, which is not in CRS's default allowed
# request content-type list (rule 920420), pushing the anomaly score to the
# default blocking threshold on every single sync request. Confirmed live
# 2026-10-12 via modsec_audit.log while testing phone sync. Scoped to just
# this endpoint and just this one rule, so the global content-type policy
# is untouched everywhere else.
# @beginsWith (not @streq, fixed 2026-10-17): real ActiveSync requests
# always carry a query string (?Cmd=Sync&...), so @streq never matched -
# rule 920420 kept firing (853 hits over 5 days per modsec_audit.log).
SecRule REQUEST_URI "@beginsWith /Microsoft-Server-ActiveSync" \
    "id:9000001,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920420"
EOF
        log "Added the ActiveSync content-type exclusion to $excl."
    else
        log "[ OK ] ActiveSync content-type exclusion already present in $excl (or file missing)."
    fi

    # grommunio-web itself POSTs to /web/index.php with Content-Type:
    # text/plain for some action, also not in CRS's default allowed list
    # (same rule 920420). Confirmed live 2026-10-12 via modsec_audit.log.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000002,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: grommunio-web itself POSTs to /web/index.php with
# Content-Type: text/plain for some action, which is not in CRS's default
# allowed request content-type list (rule 920420). Confirmed live
# 2026-10-12 via modsec_audit.log. Scoped to just this endpoint and just
# this one rule, so the global content-type policy is untouched elsewhere.
# @beginsWith for the same query-string robustness as id 9000001 above.
SecRule REQUEST_URI "@beginsWith /web/index.php" \
    "id:9000002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920420"
EOF
        log "Added the grommunio-web text/plain content-type exclusion to $excl."
    else
        log "[ OK ] grommunio-web text/plain content-type exclusion already present in $excl (or file missing)."
    fi

    # Desktop Outlook talks to gromox via MAPI/HTTP (/mapi/emsmdb/ and
    # /mapi/nspi/), same rule 920420 (content-type not in CRS's default
    # allowed list). Confirmed live 2026-10-17 via modsec_audit.log
    # (723 and 48 hits over 5 days).
    if [[ -f "$excl" ]] && ! grep -q 'id:9000003,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: desktop Outlook talks to gromox via MAPI/HTTP
# (/mapi/emsmdb/ and /mapi/nspi/), which also uses a Content-Type not in
# CRS's default allowed list (rule 920420). Confirmed live 2026-10-17 via
# modsec_audit.log (723 and 48 hits over 5 days). Scoped to just these two
# endpoints and just this one rule.
SecRule REQUEST_URI "@beginsWith /mapi/emsmdb/" \
    "id:9000003,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920420"

SecRule REQUEST_URI "@beginsWith /mapi/nspi/" \
    "id:9000004,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920420"
EOF
        log "Added the MAPI/HTTP (emsmdb+nspi) content-type exclusions to $excl."
    else
        log "[ OK ] MAPI/HTTP content-type exclusions already present in $excl (or file missing)."
    fi

    # Method enforcement (rule 911100) only allows GET HEAD POST OPTIONS by
    # default - CRS's own crs-setup.conf documents this exact override
    # mechanism (tx.allowed_methods) with worked examples for both REST
    # APIs and WebDAV. Confirmed live 2026-10-21 via modsec_audit.log: this
    # default was already blocking PUT to grommunio-admin-api (/api/...,
    # e.g. saving any setting in admin-web) and to grommunio-files's
    # WebDAV endpoint (/files/remote.php/webdav/..., i.e. every file
    # upload) - the single biggest false-positive risk found, since it's
    # not an edge case but core write functionality in two components.
    # Scoped per area (not a global override) so the general website and
    # every other grommunio endpoint keep the strict default.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000005,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: rule 911100 (method enforcement) only allows GET
# HEAD POST OPTIONS by default. grommunio-admin-api's REST API
# (/api/...) uses PUT/PATCH/DELETE for ordinary writes (saving settings,
# partial updates, deleting objects) - confirmed live 2026-10-21 via
# modsec_audit.log (PUT to /api/v1/defaults/createParams and others).
# Verbs per CRS's own crs-setup.conf documented RESTful-API example.
SecRule REQUEST_URI "@beginsWith /api" \
    "id:9000005,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"

# Added for grommunio: grommunio-files is Nextcloud-based: its WebDAV
# endpoint (/files/remote.php/webdav/...) needs the standard WebDAV verb
# set to upload/move/delete files at all - confirmed live 2026-10-21 via
# modsec_audit.log (PUT blocked on every file upload attempt). Verbs per
# CRS's own crs-setup.conf documented WebDAV example (dropping the
# version-control-only CHECKOUT/MERGE/MKACTIVITY verbs - not relevant to
# plain file storage).
SecRule REQUEST_URI "@beginsWith /files" \
    "id:9000006,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK'"

# Added for grommunio: grommunio-dav serves CalDAV/CardDAV (/dav/...),
# which needs the same WebDAV verb set as grommunio-files plus REPORT
# (used by essentially every CalDAV/CardDAV client for calendar-query/
# addressbook-query/sync-collection) and MKCALENDAR (RFC 4791) - added
# proactively alongside the others rather than waiting to observe a
# blocked REPORT in the audit log, since calendar/contacts sync breaking
# silently is worse than a slightly wider allow-list on this one path.
SecRule REQUEST_URI "@beginsWith /dav" \
    "id:9000007,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK REPORT MKCALENDAR'"
EOF
        log "Added the /api, /files and /dav method-enforcement overrides to $excl."
    else
        log "[ OK ] Method-enforcement overrides already present in $excl (or file missing)."
    fi

    # grommunio-web's own JSON API responses use Content-Type:
    # "application/json; charset=UTF-8;" (note the trailing semicolon with
    # nothing after it) - rule 920470's strict Content-Type grammar rejects
    # that trailing-semicolon form, even though it's a harmless formatting
    # quirk, not a protocol violation. Confirmed live 2026-10-21 via
    # modsec_audit.log (123 hits on /web/grommunio.php alone in a few
    # days). Scoped to just this endpoint and just this one rule.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000008,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: grommunio-web's own JSON API responses on
# /web/grommunio.php use Content-Type: "application/json; charset=UTF-8;"
# (trailing semicolon, nothing after it) - rule 920470's strict grammar
# rejects that harmless formatting quirk. Confirmed live 2026-10-21 via
# modsec_audit.log (123 hits over a few days). Scoped to just this
# endpoint and just this one rule.
SecRule REQUEST_URI "@beginsWith /web/grommunio.php" \
    "id:9000008,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=920470"
EOF
        log "Added the grommunio.php Content-Type exclusion to $excl."
    else
        log "[ OK ] grommunio.php Content-Type exclusion already present in $excl (or file missing)."
    fi

    # Rule 920450 (restricted HTTP headers) includes Accept-Charset in its
    # default restricted list (tx.restricted_headers) - CRS's own
    # crs-setup.conf documents this as an overridable tx variable. Confirmed
    # live 2026-10-21 via modsec_audit.log: a real Chrome browser loading
    # the plain webmail root (/web/) was flagged purely for sending this
    # header, which is obsolete but harmless, not a risk indicator - unlike
    # the other headers on the default list (Proxy, Lock-Token,
    # Content-Range, If), which stay restricted. Set globally, not scoped
    # to one endpoint: this header carries no meaningful risk anywhere.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000009,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: rule 920450's default restricted-header list
# includes Accept-Charset, which is obsolete but harmless (not a known
# risk indicator, unlike Proxy/Lock-Token/Content-Range/If, which stay
# restricted). Confirmed live 2026-10-21 via modsec_audit.log: a real
# Chrome browser loading the plain webmail root (/web/) was flagged
# purely for sending this header. Global, not endpoint-scoped - this
# header carries no meaningful risk anywhere on this server.
SecAction \
    "id:9000009,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.restricted_headers=/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/'"
EOF
        log "Added the Accept-Charset restricted-header override to $excl."
    else
        log "[ OK ] Accept-Charset restricted-header override already present in $excl (or file missing)."
    fi

    # Saving grommunio-web's own "defaults" (first/sur/full name) got stuck:
    # the browser never progressed past the save, no error shown. Confirmed
    # live 2026-10-26 via nginx-error.log: POST /web/grommunio.php blocked by
    # rule 949110 ("Inbound Anomaly Score Exceeded", Total Score: 15 - three
    # times the default blocking threshold of 5). 949110 is the aggregate
    # rule, not a single offending rule - several individual CRS content
    # rules (likely generic SQLi/XSS heuristics reacting to characters like
    # parentheses in a name field, e.g. "Example (EU)") each added a few
    # points, together clearing the threshold even though none of them is
    # id:9000008's already-fixed Content-Type issue. modsec_audit.log itself
    # was empty when this was investigated (truncated during an earlier
    # unrelated log-cleanup) and never recovered any detail even after
    # reproducing it live, so the exact contributing rule IDs were not
    # individually identifiable - a URI-scoped anomaly-threshold increase
    # was used instead of chasing individual rule IDs blind. Scoped to just
    # this one first-party, authenticated-only JSON backend endpoint, not a
    # global threshold change - the rest of the site keeps the strict
    # default. Rules still run and still log; they just no longer reach the
    # blocking threshold for this endpoint specifically.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000010,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: /web/grommunio.php (grommunio-web's own JSON AJAX
# backend) was hit by rule 949110 (aggregate anomaly score exceeded, Total
# Score 15 vs the default threshold of 5) when saving account defaults
# (first/sur/full name) - confirmed live 2026-10-26, saving silently never
# completed. The audit log had no detail to identify individual
# contributing rule IDs (empty at the time, including after reproducing the
# block live), so the threshold is raised for this one first-party,
# authenticated-only endpoint instead of chasing rule IDs blind. Everywhere
# else keeps the strict default threshold.
SecRule REQUEST_URI "@beginsWith /web/grommunio.php" \
    "id:9000010,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"
EOF
        log "Added the grommunio.php anomaly-score-threshold exclusion to $excl."
    else
        log "[ OK ] grommunio.php anomaly-score-threshold exclusion already present in $excl (or file missing)."
    fi

    # Adding the grommunio-files account in webmail's Files plugin got
    # "access denied": confirmed live 2026-10-26 via nginx-error.log -
    # PROPFIND /files/remote.php/webdav/ blocked by rule 949110 (aggregate
    # anomaly score exceeded, Total Score 10 vs the default threshold of
    # 5). Same class of false positive as id:9000010 above (grommunio.php)
    # - generic CRS content rules reacting to a legitimate WebDAV PROPFIND
    # request/body, not an actual attack. modsec_audit.log was again empty
    # (confirmed still 0 bytes immediately after reproducing this live, not
    # just stale from the earlier log-cleanup truncation - the audit log
    # appears to not be writing at all right now, a separate, not-yet-
    # diagnosed issue), so again no individual rule IDs could be
    # identified - same threshold-based approach as 9000010, scoped to just
    # this WebDAV endpoint.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000011,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: /files/remote.php/webdav (grommunio-files' WebDAV
# endpoint) was hit by rule 949110 (aggregate anomaly score exceeded, Total
# Score 10 vs the default threshold of 5) on a plain PROPFIND - confirmed
# live 2026-10-26, adding the account in webmail's Files plugin failed with
# "access denied". modsec_audit.log had no detail (empty), same situation
# as id:9000010 - threshold raised for just this endpoint instead of
# chasing rule IDs blind. Everywhere else keeps the strict default.
SecRule REQUEST_URI "@beginsWith /files/remote.php/webdav" \
    "id:9000011,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"
EOF
        log "Added the grommunio-files WebDAV anomaly-score-threshold exclusion to $excl."
    else
        log "[ OK ] grommunio-files WebDAV anomaly-score-threshold exclusion already present in $excl (or file missing)."
    fi

    # Same aggregate-anomaly-score false-positive class as 9000010/9000011
    # above, applied proactively to every other endpoint with a complex,
    # user-controlled request body that could trip the same generic CRS
    # content heuristics (SQLi/XSS-style rules reacting to ordinary
    # characters in names/XML/JSON, not an actual attack):
    #   - ActiveSync: confirmed live 2026-10-25 (real phone FolderSync
    #     blocked, anomaly score 5) - the existing id:9000001 only fixed
    #     the Content-Type issue (920420), never the aggregate score.
    #   - /dav (CalDAV/CardDAV): REPORT queries (sync-collection,
    #     calendar-query) carry complex XML bodies, same risk as the
    #     WebDAV PROPFIND that just broke grommunio-files.
    #   - /api (grommunio-admin-api): the exact same "special characters
    #     in a name field" issue that broke grommunio-web's defaults-save
    #     (id:9000010) could equally happen here - e.g. the 21 users/11
    #     domains with varied names created via this API.
    #   - /mapi (desktop Outlook MAPI/HTTP) and /EWS/Exchange.asmx: not
    #     yet observed blocked, but same shape of risk as ActiveSync/MAPI
    #     content-type issues already found for these two.
    #   - /Autodiscover: not yet observed blocked, matched case-
    #     insensitively (t:lowercase) since nginx's own location for it
    #     is also case-insensitive (~*) and real clients vary in casing.
    # Not yet individually confirmed live for every one of these (unlike
    # 9000010/9000011, which were) - applied proactively given the
    # established, repeated pattern, rather than waiting for each one to
    # visibly break first.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000012,' "$excl"; then
        cat >> "$excl" <<'EOF'

# Added for grommunio: same aggregate-anomaly-score false-positive class as
# id:9000010/9000011 (grommunio.php, files/webdav) - applied proactively to
# every other grommunio endpoint with a complex, user-controlled request
# body, rather than waiting for each to visibly break first. See
# 39-nginx-modsecurity.sh for the full reasoning and which of these were
# actually confirmed blocked live vs. applied proactively.
SecRule REQUEST_URI "@beginsWith /Microsoft-Server-ActiveSync" \
    "id:9000012,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"

SecRule REQUEST_URI "@beginsWith /dav" \
    "id:9000013,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"

SecRule REQUEST_URI "@beginsWith /api" \
    "id:9000014,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"

SecRule REQUEST_URI "@beginsWith /mapi" \
    "id:9000015,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"

SecRule REQUEST_URI "@beginsWith /EWS/Exchange.asmx" \
    "id:9000016,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"

SecRule REQUEST_URI "@beginsWith /autodiscover" \
    "id:9000017,\
    phase:1,\
    pass,\
    nolog,\
    t:lowercase,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"
EOF
        log "Added the ActiveSync/dav/api/mapi/EWS/Autodiscover anomaly-score-threshold exclusions to $excl."
    else
        log "[ OK ] ActiveSync/dav/api/mapi/EWS/Autodiscover anomaly-score-threshold exclusions already present in $excl (or file missing)."
    fi

    # Real false positive found live 2026-10-29: uploading a FortiGate
    # VPN config (.txt) via WebDAV (webmail's Files app) was blocked
    # - not by the anomaly-score threshold (already raised to 25 by
    # id:9000011 above), but by the FILE'S OWN CONTENT being scanned as
    # attack payload: "set proposal ...", "set dhgrp 14"-style config
    # syntax plus embedded newlines/quotes tripped 5 separate generic CRS
    # rules at once (932105/932115 command injection, 941160 XSS, 921150
    # CR/LF header injection, 920170 "GET or HEAD with body" despite this
    # being a PUT) for a combined score of 130 - nowhere close to
    # survivable by just raising the threshold further. Root cause: this
    # is an upload endpoint - the body IS an arbitrary user file, not a
    # structured request that attack-pattern rules should ever inspect.
    # Fix (the standard, documented approach for WebDAV/file-upload
    # endpoints behind ModSecurity): skip request body inspection entirely
    # for PUT requests to this path specifically - method-scoped (chain),
    # so PROPFIND/MKCOL/DELETE etc. on the same path keep full inspection
    # of their own (small, predictable) bodies. Verified live: re-uploaded
    # equivalent VPN-config content via a real WebDAV PUT with real
    # credentials - 201 Created, confirmed written to disk, then deleted
    # again as cleanup.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000020,' "$excl"; then
        cat >> "$excl" <<'EOF'

# grommunio-files WebDAV uploads: skip request body inspection for PUT
# (the body is an arbitrary user file, not a structured request content
# attack-pattern rules should ever scan) - found 2026-10-29, a legitimate
# FortiGate VPN config upload scored 130 purely from its own config
# syntax (multiple generic command-injection/XSS/header-injection rules),
# far beyond any reasonable anomaly-score threshold. Method-scoped via
# chain so PROPFIND/MKCOL/DELETE on the same path keep full inspection.
SecRule REQUEST_METHOD "@streq PUT" \
    "id:9000020,\
    phase:1,\
    pass,\
    nolog,\
    chain"
    SecRule REQUEST_URI "@beginsWith /files/remote.php/webdav" \
        "ctl:requestBodyAccess=Off"
EOF
        log "Added the WebDAV PUT requestBodyAccess=Off exclusion to $excl."
    else
        log "[ OK ] WebDAV PUT requestBodyAccess=Off exclusion already present in $excl (or file missing)."
    fi

    # Same false-positive class, found live 2026-10-29 right after the
    # WebDAV one above: an in-progress webmail draft (pasted technical
    # text - an SPF record analysis, arrows, multi-line "a:" syntax -
    # plus an embedded profile image as a base64 data: URI) got blocked
    # on /web/grommunio.php, score 35 (above the 25 threshold id:9000010
    # already sets here) - RCE/XSS rules matching the pasted text's
    # structure, XSS attribute-injection matching the base64 image.
    # grommunio.php is the ONE AJAX backend for all of webmail (compose,
    # save, send, read) - users can legitimately type/paste/embed anything
    # into an email body. Disabling body inspection here is safe for the
    # same reason as WebDAV: this endpoint is session-authenticated only
    # (no anonymous access), so URI/method/auth remain the real defence;
    # body-content heuristics add little against an already-authenticated
    # client while causing recurring false positives on ordinary mail
    # content. Scoped to POST (every real call here is POST) so nothing
    # else on this path loses inspection unexpectedly.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000021,' "$excl"; then
        cat >> "$excl" <<'EOF'

# grommunio-web's AJAX backend: skip request body inspection for POST -
# found 2026-10-29, a real webmail draft (pasted technical text + an
# embedded base64 image) scored 35 purely from its own content, above
# the id:9000010 threshold. This is the one backend for all of webmail
# (compose/save/send/read) - users can legitimately put anything in a
# mail body. Session-authenticated only, so URI/method/auth remain the
# real defence here, not body-content heuristics.
SecRule REQUEST_METHOD "@streq POST" \
    "id:9000021,\
    phase:1,\
    pass,\
    nolog,\
    chain"
    SecRule REQUEST_URI "@beginsWith /web/grommunio.php" \
        "ctl:requestBodyAccess=Off"
EOF
        log "Added the grommunio.php POST requestBodyAccess=Off exclusion to $excl."
    else
        log "[ OK ] grommunio.php POST requestBodyAccess=Off exclusion already present in $excl (or file missing)."
    fi

    # Real (harmless) false positive found live 2026-10-30: every WebDAV
    # PROPFIND to /files/remote.php/webdav fires rule 921110 "HTTP Request
    # Smuggling Attack" - a generic CRS rule that looks for a second HTTP
    # request line hidden inside the body. PROPFIND's own XML body
    # literally contains the text "propfind xmlns:d=..." right after a
    # newline, which the rule's regex (method-name + path-like token +
    # newline) matches on - a structural property of WebDAV's own
    # protocol, not an actual smuggling attempt. Severity 2, well under
    # even the default anomaly-score threshold (5), so nothing was ever
    # blocked by it - a 591-entry audit-log sweep (2026-10-30) found 33
    # hits today, all status 207 (succeeded normally). Removing this one
    # rule ID for this one method+endpoint combo is more precise than
    # raising the threshold further (id:9000011 already does that, for a
    # different, unrelated false positive on the same endpoint) - every
    # other rule still inspects PROPFIND normally here.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000022,' "$excl"; then
        cat >> "$excl" <<'EOF'

# grommunio-files WebDAV PROPFIND: remove rule 921110 (HTTP Request
# Smuggling Attack) for this one method+endpoint - found 2026-10-30, every
# PROPFIND's own XML body ("propfind xmlns:d=...") structurally matches
# the rule's "hidden second request line" regex. Severity 2, never
# actually blocked anything, purely log noise. Method-scoped via chain so
# other methods on this path keep this rule active.
SecRule REQUEST_METHOD "@streq PROPFIND" \
    "id:9000022,\
    phase:1,\
    pass,\
    nolog,\
    chain"
    SecRule REQUEST_URI "@beginsWith /files/remote.php/webdav" \
        "ctl:ruleRemoveById=921110"
EOF
        log "Added the WebDAV PROPFIND rule-921110 exclusion to $excl."
    else
        log "[ OK ] WebDAV PROPFIND rule-921110 exclusion already present in $excl (or file missing)."
    fi

    # Real false positive found live 2026-10-30: grommunio-admin-api's own
    # "chat" module (chat.yaml, the api.admin integration) could not reach
    # grommunio-chat-v10's REST API at all - every call blocked 403.
    # Root cause confirmed via the modsec audit log: rule 920170 ("GET or
    # HEAD Request with Body Content") fired because the chat API client
    # (Mattermost's own Go SDK, which grommunio-chat-v10 is based on) sends
    # a non-zero Content-Length header on GET requests - a known quirk of
    # that client library, not an attack. Same false-positive class as the
    # ActiveSync/dav/api/mapi/EWS/Autodiscover exclusions above
    # (id:9000012-9000017) - /chat was never added there since this is the
    # first time this project touched grommunio-chat.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000023,' "$excl"; then
        cat >> "$excl" <<'EOF'

# grommunio-chat-v10's own REST API client (Mattermost's Go SDK) sends a
# non-zero Content-Length on GET requests - found 2026-10-30, blocked
# grommunio-admin-api's own chat integration (chat.yaml/api.admin) with a
# 403 on every call. Same false-positive class as the other proactive
# exclusions above.
SecRule REQUEST_URI "@beginsWith /chat" \
    "id:9000023,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"
EOF
        log "Added the grommunio-chat anomaly-score-threshold exclusion to $excl."
    else
        log "[ OK ] grommunio-chat anomaly-score-threshold exclusion already present in $excl (or file missing)."
    fi

    # Real false positive found live 2026-11-11: uploading a file via
    # WebDAV from a mobile/tablet client's Files app failed, while
    # logging in and creating a folder both worked. id:9000020/9000011
    # above already fix this exact class of problem for WebDAV, but only
    # for /files/remote.php/webdav - the older WebDAV endpoint. Mobile/
    # tablet clients instead use grommunio-files' newer DAV endpoint,
    # /files/remote.php/dav/files/<user>/..., a different URI prefix the
    # existing @beginsWith patterns never matched. Confirmed via
    # modsec-audit.log (Concurrent mode): a PUT upload tripped id 920170
    # ("GET or HEAD Request with Body Content", despite being a PUT),
    # 920420 (Content-Type application/octet-stream not in CRS's allowed
    # list) and 921110 ("HTTP Request Smuggling Attack", matched against
    # the uploaded file's own body content, not an actual attack) for a
    # combined score of 15 against the default threshold of 5. Same two
    # exclusions as the webdav endpoint already has, now also for dav.
    if [[ -f "$excl" ]] && ! grep -q 'id:9000024,' "$excl"; then
        cat >> "$excl" <<'EOF'

# grommunio-files DAV uploads (the newer endpoint, used by mobile/tablet
# clients - distinct from /files/remote.php/webdav already covered by
# id:9000020): skip request body inspection for PUT, same reasoning as
# id:9000020. Found 2026-11-11.
SecRule REQUEST_METHOD "@streq PUT" \
    "id:9000024,\
    phase:1,\
    pass,\
    nolog,\
    chain"
    SecRule REQUEST_URI "@beginsWith /files/remote.php/dav" \
        "ctl:requestBodyAccess=Off"
EOF
        log "Added the WebDAV (dav) PUT requestBodyAccess=Off exclusion to $excl."
    else
        log "[ OK ] WebDAV (dav) PUT requestBodyAccess=Off exclusion already present in $excl (or file missing)."
    fi

    if [[ -f "$excl" ]] && ! grep -q 'id:9000025,' "$excl"; then
        cat >> "$excl" <<'EOF'

# grommunio-files DAV endpoint (the newer /files/remote.php/dav, distinct
# from /files/remote.php/webdav already covered by id:9000011): same
# aggregate-anomaly-score false-positive class, for non-PUT DAV verbs
# (PROPFIND, MKCOL, REPORT, DELETE, MOVE) on this endpoint. Found
# 2026-11-11, applied proactively alongside id:9000024 rather than
# waiting for each verb to break individually.
SecRule REQUEST_URI "@beginsWith /files/remote.php/dav" \
    "id:9000025,\
    phase:1,\
    pass,\
    nolog,\
    setvar:'tx.inbound_anomaly_score_threshold=25'"
EOF
        log "Added the grommunio-files DAV anomaly-score-threshold exclusion to $excl."
    else
        log "[ OK ] grommunio-files DAV anomaly-score-threshold exclusion already present in $excl (or file missing)."
    fi
    finalize_backup "$excl"

    mkdir -p /etc/nginx/modsec

    # SecAuditLogStorageDir target for the Concurrent audit log above -
    # must exist and be writable by the nginx worker (www-data) before
    # the first reload, or ModSecurity silently fails to write there.
    install -d -o www-data -g adm -m 0750 /var/log/nginx/modsec-audit

    # Concurrent mode creates one small file per logged transaction, under
    # a daily/hourly directory tree - nothing rotates these on its own
    # (the stock /etc/logrotate.d/nginx only globs "*.log", and even a
    # dedicated logrotate stanza doesn't work here: tested live 2026-10-29,
    # `maxage` only prunes already-ROTATED backup copies, e.g. ".1"/".2.gz"
    # - it never removes a plain file matched fresh by a wildcard that
    # logrotate hasn't rotated itself, confirmed with a deliberately
    # 20-day-old test file that logrotate -d still reported as "already
    # rotated" and left alone).
    #
    # First tried /etc/cron.daily/ (the usual Debian place for this) -
    # WRONG for this box specifically, found live 2026-10-29: there is no
    # cron daemon at all here (no `cron` package, no `/etc/crontab`, no
    # anacron, `crontab -l` itself is "command not found") - this Debian
    # 13 install relies entirely on systemd timers for scheduled
    # maintenance. `logrotate.timer` itself (package-shipped, confirmed by
    # reading it directly) proves this: OnCalendar=daily,
    # RandomizedDelaySec=1h, Persistent=true - a cron.daily script here
    # would simply never run. Matched that exact same timer shape instead.
    local AUDIT_CLEAN_SCRIPT="/root/bin/clean-modsec-audit.sh"
    local AUDIT_CLEAN_NEW
    AUDIT_CLEAN_NEW="$(mktemp)"
    cat > "$AUDIT_CLEAN_NEW" <<'SCRIPT'
#!/usr/bin/env bash
# Managed by 39-nginx-modsecurity.sh. Prunes ModSecurity's Concurrent
# audit log files (one per transaction) older than 14 days, matching
# /etc/logrotate.d/nginx's own retention, then removes any directories
# left empty by that. Run via clean-modsec-audit.timer (systemd, matching
# logrotate.timer's own shape) - this box has no cron daemon at all.
set -euo pipefail
DIR="/var/log/nginx/modsec-audit"
[[ -d "$DIR" ]] || exit 0
find "$DIR" -type f -mtime +14 -delete
find "$DIR" -mindepth 1 -type d -empty -delete
SCRIPT
    if ! cmp -s "$AUDIT_CLEAN_NEW" "$AUDIT_CLEAN_SCRIPT" 2>/dev/null; then
        backup_file "$AUDIT_CLEAN_SCRIPT"
        install -m 0755 "$AUDIT_CLEAN_NEW" "$AUDIT_CLEAN_SCRIPT"
        finalize_backup "$AUDIT_CLEAN_SCRIPT"
        log "[ OK ] Wrote $AUDIT_CLEAN_SCRIPT."
    else
        log "[ OK ] $AUDIT_CLEAN_SCRIPT already correct."
    fi
    rm -f "$AUDIT_CLEAN_NEW"
    rm -f /etc/cron.daily/clean-modsec-audit

    local AUDIT_CLEAN_SERVICE="/etc/systemd/system/clean-modsec-audit.service"
    local AUDIT_CLEAN_TIMER="/etc/systemd/system/clean-modsec-audit.timer"
    local AUDIT_CLEAN_UNITS_CHANGED=0
    local AUDIT_CLEAN_SERVICE_NEW
    AUDIT_CLEAN_SERVICE_NEW="$(mktemp)"
    cat > "$AUDIT_CLEAN_SERVICE_NEW" <<'UNIT'
[Unit]
Description=Prune old ModSecurity Concurrent audit log files

[Service]
Type=oneshot
ExecStart=/root/bin/clean-modsec-audit.sh
UNIT
    if ! cmp -s "$AUDIT_CLEAN_SERVICE_NEW" "$AUDIT_CLEAN_SERVICE" 2>/dev/null; then
        backup_file "$AUDIT_CLEAN_SERVICE"
        install -m 0644 "$AUDIT_CLEAN_SERVICE_NEW" "$AUDIT_CLEAN_SERVICE"
        finalize_backup "$AUDIT_CLEAN_SERVICE"
        AUDIT_CLEAN_UNITS_CHANGED=1
        log "[ OK ] Wrote $AUDIT_CLEAN_SERVICE."
    else
        log "[ OK ] $AUDIT_CLEAN_SERVICE already correct."
    fi
    rm -f "$AUDIT_CLEAN_SERVICE_NEW"

    local AUDIT_CLEAN_TIMER_NEW
    AUDIT_CLEAN_TIMER_NEW="$(mktemp)"
    cat > "$AUDIT_CLEAN_TIMER_NEW" <<'UNIT'
[Unit]
Description=Daily prune of old ModSecurity Concurrent audit log files

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
    if ! cmp -s "$AUDIT_CLEAN_TIMER_NEW" "$AUDIT_CLEAN_TIMER" 2>/dev/null; then
        backup_file "$AUDIT_CLEAN_TIMER"
        install -m 0644 "$AUDIT_CLEAN_TIMER_NEW" "$AUDIT_CLEAN_TIMER"
        finalize_backup "$AUDIT_CLEAN_TIMER"
        AUDIT_CLEAN_UNITS_CHANGED=1
        log "[ OK ] Wrote $AUDIT_CLEAN_TIMER."
    else
        log "[ OK ] $AUDIT_CLEAN_TIMER already correct."
    fi
    rm -f "$AUDIT_CLEAN_TIMER_NEW"

    if [[ "$AUDIT_CLEAN_UNITS_CHANGED" -eq 1 ]]; then
        systemctl daemon-reload
    fi
    systemctl enable --now clean-modsec-audit.timer

    local load="/etc/nginx/modsec/main.conf"
    local load_wanted
    load_wanted="$(cat <<'EOF'
# Written by 39-nginx-modsecurity.sh.
# Chains modsecurity.conf + OWASP CRS. We do not use modsecurity-crs's own
# /usr/share/modsecurity-crs/owasp-crs.load: it uses IncludeOptional, an
# Apache mod_security2-only directive that nginx's ModSecurity v3 connector
# does not understand (nginx -t: "Invalid input"). Plain Include works for
# the same files, which all exist (shipped by modsecurity-crs itself).
Include /etc/nginx/modsecurity.conf

# Overrides the package's own DetectionOnly default (set in the Include
# above). DetectionOnly ran live on testvps from 2026-10-12 to 2026-10-21
# specifically to tune away false positives using real traffic (see the
# id:9000001-9000009 exclusions below) before ever blocking anything -
# that tuning is now done and proven (nginx -t + reload + webmail/admin-web
# smoke-tested clean after each change), so a fresh provision starts
# straight in blocking mode with the same tuning already in place, rather
# than repeating the multi-day observe-then-flip process every time.
SecRuleEngine On

# Overrides the package's own body-size defaults (set in the Include
# above: SecRequestBodyLimit 13107200 = 12.5MB, SecRequestBodyNoFilesLimit
# 131072 = 128KB - confirmed 2026-11-11 to be byte-identical to the
# package's own shipped reference config, so these were never tuned
# before now). SecRequestBodyNoFilesLimit governs any request body that
# is NOT multipart/form-data - which is exactly what a WebDAV PUT is
# (grommunio-files uploads, see id:9000024/9000025 above): the file's
# raw bytes ARE the entire body, so a 128KB cap blocked any real file,
# found live 2026-11-11 uploading a PDF ebook via WebDAV from a mobile
# client. There is no documented per-transaction ctl override for this
# in libmodsecurity v3 (ctl:requestBodyLimit is v2-only and is a parse
# error on v3) - raising the global directive is the only documented
# fix. Target: 150MB (157286400 bytes), matching Microsoft 365's own
# documented message-size limit - confirmed via Microsoft's own docs
# that their 150MB is the already-encoded/transmitted size (not the
# pre-encoding attachment size), i.e. the same quantity Postfix's own
# message_size_limit measures (already exactly 150MB, unchanged) and
# the same quantity a WebDAV PUT body is (no base64/MIME encoding layer
# for WebDAV, unlike SMTP) - so 150MB literal is correct here with no
# further encoding-overhead adjustment needed, unlike Postfix.
SecRequestBodyLimit 157286400
SecRequestBodyNoFilesLimit 157286400

# REAL GAP FOUND 2026-10-29: modsec_audit.log (SecAuditLogType Serial, set
# in the package's own /etc/nginx/modsecurity.conf) has been completely
# empty (0 bytes) since at least 2026-10-26, despite correct
# SecAuditEngine/SecAuditLogParts/SecAuditLogRelevantStatus config and
# confirmed real blocks happening constantly (nginx-error.log has them).
# This file's own earlier comments (2026-10-12 to -21) show
# modsec_audit.log DID work at some point - this is a regression, not a
# config mistake of ours. Root cause: ModSecurity-nginx v1.0.3 +
# libmodsecurity3 3.0.14 (confirmed exact versions live) has a
# long-standing, widely-reported issue where `SecAuditLogType Serial`
# silently produces no output with this connector - `Concurrent` mode
# (one file per transaction, under a date-based directory tree) is the
# documented workaround and was verified live: switching to it made a
# real 403 block immediately produce a readable, detailed file (full
# matched-rule info, request headers, response body).
#
# NOTE this also means these per-transaction files include full request
# headers verbatim, including session cookies/auth tokens for any blocked
# authenticated request - confirmed live reading one. This had to be
# fixed outright, not just noted: those tokens must never land in logs.
#
# Tried and REJECTED 2026-10-29: ModSecurity's documented per-header
# redaction action, `sanitiseRequestHeader` (and `sanitiseMatched`,
# tried as a fallback) - both confirmed live to fail `nginx -t` with
# "Action: Sanitise... is not yet supported." This libmodsecurity3 build
# (3.0.14) has the Sanitise* action names in its grammar but none of them
# are actually implemented - a real, confirmed gap in the library itself,
# not a syntax mistake (verified by testing both, immediately reverted
# since nginx -t fails before any reload - no live impact either time).
#
# Used instead: drop part B (request headers) from SecAuditLogParts
# entirely. This is the only mechanism this library build actually
# implements that GUARANTEES Cookie/Authorization never reach the audit
# log, at the cost of losing all other request headers too (User-Agent,
# Referer, etc.) for every logged transaction - an explicit, deliberate
# trade-off for a hard requirement, not a partial/best-effort fix.
SecAuditLogType Concurrent
SecAuditLogStorageDir /var/log/nginx/modsec-audit/
SecAuditLogParts AIJDEFHZ

Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
EOF
)"
    if [[ ! -f "$load" ]] || [[ "$(cat "$load")" != "$load_wanted" ]]; then
        backup_file "$load"
        echo "$load_wanted" > "$load"
        finalize_backup "$load"
        log "Wrote $load (modsecurity.conf + OWASP CRS, nginx-safe Include lines)."
    else
        log "[ OK ] $load already up to date."
    fi

    local conf="/etc/nginx/conf.d/modsecurity.conf"
    local wanted
    wanted="$(cat <<'EOF'
# Written by 39-nginx-modsecurity.sh. Applies to every vhost (http{} context):
# both the general website and every grommunio vhost, the admin's choice.
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
EOF
)"
    if [[ ! -f "$conf" ]] || [[ "$(cat "$conf")" != "$wanted" ]]; then
        backup_file "$conf"
        echo "$wanted" > "$conf"
        finalize_backup "$conf"
        log "Wrote $conf (modsecurity on, OWASP CRS, for every vhost)."
    else
        log "[ OK ] $conf already up to date."
    fi

    nginx -t || die "nginx -t failed after enabling ModSecurity - check $conf and $load."
    systemctl reload nginx || die "nginx reload failed after enabling ModSecurity."

    if grep -q '^SecRuleEngine On$' "$load" 2>/dev/null; then
        log "[ OK ] SecRuleEngine is On (blocking) - tuned via ids 9000001-9000009 in $excl."
    else
        log "NOTE: SecRuleEngine override not found in $load - check it; this step expects to set blocking mode explicitly, not rely on the package default."
    fi

    # ============================================================
    # fail2ban integration: a ModSecurity block only rejects that one
    # request by itself - found 2026-10-21 that nothing fed this into the
    # firewall, so a scanner tripping WAF rules repeatedly was never
    # actually banned (none of the existing jails watch modsec_audit.log;
    # they coincidentally catch some of the same traffic only by matching
    # specific URL patterns independently, e.g. grommunio-admin-web-scan).
    #
    # modsec_audit.log's own "Access denied" lines don't carry the client
    # IP (ModSecurity's "hostname" field there is actually this server's
    # own address, confirmed live) - nginx's error log does, on the exact
    # same "Access denied" line, in standard "client: <IP>," form (the
    # ModSecurity nginx connector logs there too). Regex verified
    # 2026-10-21 with fail2ban-regex against a real block on testvps
    # (an SSTP VPN scanner probe, 2 different source IPs, same URI).
    # ============================================================
    require_cmd fail2ban-client

    local FW_CFG FW_BACKEND banaction
    FW_CFG="$(cfg_file 20-firewall-fail2ban)"
    FW_BACKEND=""
    if [[ -f "$FW_CFG" ]]; then
        # shellcheck disable=SC1090
        source "$FW_CFG"
    fi
    if [[ -z "${FW_BACKEND:-}" ]]; then
        err "Could not determine the firewall backend - $FW_CFG not found or empty."
        die "Run step 20 (firewall/fail2ban) first."
    fi
    case "$FW_BACKEND" in
        firewalld) banaction="firewallcmd-ipset" ;;
        ufw)       banaction="ufw" ;;
        *)         die "Unknown firewall backend in $FW_CFG: $FW_BACKEND" ;;
    esac

    local f2b_filter="/etc/fail2ban/filter.d/nginx-modsecurity.conf"
    local f2b_filter_wanted
    f2b_filter_wanted="$(cat <<'EOF'
# Verified 2026-10-21 with fail2ban-regex against a real ModSecurity block
# in /var/log/nginx/nginx-error.log on testvps (an SSTP VPN scanner probe).
# modsec_audit.log's own "Access denied" lines do not carry the client IP
# (its "hostname" field is this server's own address) - nginx's error log
# does, on the same line, in standard "client: <IP>," form.
[INCLUDES]
before = common.conf

[Definition]
failregex = ModSecurity: Access denied .*, client: <HOST>,
ignoreregex =
EOF
)"
    if [[ ! -f "$f2b_filter" ]] || [[ "$(cat "$f2b_filter")" != "$f2b_filter_wanted" ]]; then
        if [[ -f "$f2b_filter" ]]; then
            backup_file "$f2b_filter"
        fi
        echo "$f2b_filter_wanted" > "$f2b_filter"
        finalize_backup "$f2b_filter"
        log "Wrote $f2b_filter."
    else
        log "[ OK ] $f2b_filter already up to date."
    fi

    local f2b_jail="/etc/fail2ban/jail.d/zz-nginx-modsecurity-hardening.local"
    local f2b_jail_wanted
    f2b_jail_wanted="$(cat <<EOF
# Managed by server-setup.sh / 39-nginx-modsecurity.sh - do not edit.
# Bans IPs that trip ModSecurity's own blocking (not detection) threshold
# - see filter.d/nginx-modsecurity.conf for how this was verified. Ports
# cover every vhost ModSecurity sits in front of (webmail 80/443,
# admin-web/-api 8080/8443), same set as grommunio-admin-api's own jail.
# maxretry/findtime/bantime match grommunio-admin-web-scan's convention
# for scan/attack-pattern jails (feeds recidive for repeat offenders).

[nginx-modsecurity]
enabled = true
backend = auto
logpath = /var/log/nginx/nginx-error.log
port = 80,443,8080,8443
banaction = ${banaction}
# bantime widened to 24h (2026-11-05, same reasoning as postfix-smtp-auth's
# own widening the same day): findtime is already 8h, so a 1h ban was just
# churn - old failures keep counting toward the next ban regardless.
bantime = 24h
# findtime widened from 1h (2026-10-30): a full-log sweep found several IPs
# (e.g. 176.65.139.160, 8 hits) spread hours to days apart, confirmed via
# raw timestamps as deliberate pacing just outside the old 1h window - same
# evasion pattern already fixed for sshd/postfix-abuse/nginx-bad-request/
# nginx-catchall-scan.
findtime = 8h
maxretry = 3
EOF
)"
    if [[ ! -f "$f2b_jail" ]] || [[ "$(cat "$f2b_jail")" != "$f2b_jail_wanted" ]]; then
        if [[ -f "$f2b_jail" ]]; then
            backup_file "$f2b_jail"
        fi
        echo "$f2b_jail_wanted" > "$f2b_jail"
        chmod 644 "$f2b_jail"
        finalize_backup "$f2b_jail"
        log "Wrote $f2b_jail."
    else
        log "[ OK ] $f2b_jail already up to date."
    fi

    fail2ban-client -t || die "fail2ban-client -t failed after adding the nginx-modsecurity jail."

    if [[ "$banaction" == "firewallcmd-ipset" ]]; then
        firewalld_jail_sets nginx-modsecurity=80,443,8080,8443
        firewall-cmd --reload >/dev/null
    fi

    systemctl restart fail2ban || die "fail2ban restart failed after adding the nginx-modsecurity jail."
    sleep 1
    fail2ban-client status nginx-modsecurity >/dev/null 2>&1 \
        || die "nginx-modsecurity jail did not come up - check 'fail2ban-client status nginx-modsecurity'."
    log "[ OK ] nginx-modsecurity jail active - a ModSecurity block now reaches the firewall after 3 strikes in 1h (not just that one request)."

    log "ModSecurity + OWASP CRS active (blocking), fed into fail2ban/the firewall. Watch /var/log/nginx/modsec_audit.log for anything blocked that shouldn't be - add a new scoped exclusion in $excl the same way as ids 9000001-9000009 if a new false positive turns up."
}
