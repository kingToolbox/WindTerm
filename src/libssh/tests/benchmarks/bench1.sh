export CIPHER=aes128-cbc
export DEST=localhost

echo "Upload raw SSH statistics"
echo "local machine: `uname -a`"
echo "Cipher : $CIPHER ; Destination : $DEST (`ssh $DEST uname -a`)"
echo "Local ssh version: `ssh -V 2>&1`"
echo "Ping latency to $DEST":
ping -q -c 1 -n $DEST
echo "Destination $DEST SSHD vesion : `echo | nc $DEST 22 | head -n1`"
echo "ssh login latency :`(time -f user:%U ssh $DEST 'id > /dev/null') 2>&1`"
./generate.py | dd bs=4096 count=100000 | time ssh -c $CIPHER $DEST "dd bs=4096 of=/dev/null" 2>&1

