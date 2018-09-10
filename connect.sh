eval $( ./gp-okta.py gp-okta.conf )
sudo openconnect --protocol=gp --usergroup=gateway "$HOST"  --cookie "$COOKIE" --cafile "$CAFILE"
