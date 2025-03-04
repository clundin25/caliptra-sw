# Licensed under the Apache-2.0 license

#!/bin/bash

cd /home/runner
su runner -l -c "export"
su runner -l -c "/home/runner/actions-runner/run.sh --jitconfig '${JITCONFIG}'"

shutdown -h now
