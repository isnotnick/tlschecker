#!/bin/bash
# Build cert owners map
echo -e 'package tlschecker\n\nvar CertificateOwner = map[string]string{' >certificateowners.go
psql "host=crt.sh port=5432 dbname=certwatch user=guest" -tA -F ' ' -c "SELECT DISTINCT ON (encode(cert_sha256::bytea, 'hex')) CHR(34) ||  encode(cert_sha256::bytea, 'hex') || CHR(34) || CHR(58), CHR(34) || included_certificate_owner || CHR(34) || CHR(44) FROM ccadb_certificate WHERE included_certificate_owner IS NOT NULL;" >>certificateowners.go
echo -e '}' >>certificateowners.go