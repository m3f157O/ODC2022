#!/bin/bash
docker build -t ctf .
docker run -t -d ctf
