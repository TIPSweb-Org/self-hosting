#!/bin/bash
docker build -t tips .
docker run -d -p 3000:3000 --env-file .env tips