#!/bin/bash
for i in {0..38}
do
	for j in {31..126}
	do
		python3 easycat.py $j $i
	done
done
	
