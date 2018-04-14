#!/bin/bash

# Make sure the node for the first serial port is there.

rm /dev/ttyS0

# Lunix:TNG nodes: 16 sensors, each has 3 nodes.
for sensor in $(seq 0 1 15); do
	rm /dev/lunix$sensor-batt
	rm /dev/lunix$sensor-temp
	rm /dev/lunix$sensor-light
done
