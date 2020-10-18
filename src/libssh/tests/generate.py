#!/usr/bin/python
import os
a=""
for i in xrange(4096):
	a+=chr(i % 256);
while True:
	try:
		os.write(1,a)
	except:
		exit(0)
