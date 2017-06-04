#!/bin/bash

tmux new-session -d -s "dbg" "gdb $1;/bin/bash"
tmux split-window -h -t "dbg" -p 50 "voltron view register -i;/bin/bash"
tmux select-pane -t 1 
tmux split-window -v -t "dbg" -p 60 "voltron view stack;/bin/bash"
tmux select-pane -t 2 
tmux split-window -v -t "dbg" -p 30 "voltron view bt;/bin/bash"
tmux select-pane -t 0
tmux attach-session -t "dbg"

