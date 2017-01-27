#!/bin/bash

cd "$(dirname "$0")"
src=malware@magento.buq.eu

# copies & deletes, not atomic!
rsync -va $src:incoming/malware/ ../corpus/incoming/ &&
ssh $src find incoming/malware/ -type f -delete

