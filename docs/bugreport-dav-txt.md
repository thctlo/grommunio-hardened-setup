# Draft bug report: DNS check "DAV TXT" in the grommunio admin web interface

Not sent. Draft for later.

## Summary
The DNS check "DAV TXT" (CalDAV/CardDAV) only accepts the exact value `"path=/dav"`. A record using the full URL
(`https://mail.<domain>/dav`) is not recognized as found. The check then stays on **Optional**, even though the
record exists in DNS.

## Where it is (testvps, grommunio-admin-web 5.1.20)
- Frontend, chunk `159.b00fc1cd.chunk.js`: the color of "DAV TXT" is determined with
  `W('"path=/dav"'===dnsCheck.caldavTXT.externalDNS, '"path=/dav"'===dnsCheck.caldavTXT.internalDNS, "opt", "opt")`.
  The value must therefore be literally `"path=/dav"`, including the quotation marks.
- Backend, `tools/dnsHealth.py`: `checkCaldavTxt` and `checkCarddavTxt` only query `_caldavs._tcp.<domain>` and
  `_carddavs._tcp.<domain>`. The example text in the web interface names four record names (`_caldav`, `_caldavs`,
  `_carddav`, `_carddavs`), but the check only looks at two of them.
- The severity level is always `opt`, even when the record is missing. A missing record is therefore never shown
  as an error, only as optional.

## Consequence
- A record using the URL form, which is commonly used in practice, is treated as "not found".
- A missing DAV record goes unnoticed.

## Proposal
1. Also accept the URL form: check that the value contains `path=`, or that the URL resolves to the server's own
   DAV endpoint (`https://<host>/dav`). The server knows its own DAV URL, so it can compare against that itself.
2. Check all four record names listed in the example text.
3. Show a missing record as an error (red) when the DAV service is enabled for the domain (`privDav`).
4. Note on the standard: RFC 6764 uses `path=/dav` with the host taken from the SRV record. That is the form the
   check currently implements. The URL form used in our own records was therefore not compliant - a nuance worth
   noting in the report: the check is consistent with the standard.

## Reproduction
1. Set `_caldavs._tcp.<domain>` TXT to `"https://mail.<domain>/dav"`.
2. Open the domain's DNS check in the admin web interface.
3. "DAV TXT" shows as **Optional**. Change the value to `"path=/dav"`: it turns green.

## Environment
- grommunio-admin-web 5.1.20, grommunio-admin-api 1.21.25, Debian 13, testvps (2026-10-04).
