---
title: "tmux"
date: 2020-07-16T13:41:37+02:00
draft: true
---

#### Tmux
##### New session
```
tmux
tmux new -s <name>
```
##### List sessions
```tmux ls```
##### Attach to session
```
tmux a
tmux a -t <name>
```
##### Detach from session
```<ctrl+b>, d```
##### Kill session
```tmux kill-session -t 0```

#### Within a session
##### New Session
```<ctrl-b> :new```
##### Create Window
```<ctrl+b>, c```
##### Switch Window
```<ctrl+b>, 1```
##### Name Window
```<ctrl+b>, ,```
##### Vertical Split
```<ctrl+b>, %```
##### Horizontal Split
```<ctrl+b>, "```
##### Move to
```<ctrl+b>, ← ↑ → ↓```
##### Switch to next session
```<ctrl-b> )```
##### Switch to previous session
```<ctrl-b> (```
##### Rename session
```<ctrl+b>, $```
##### Kill session
```<ctrl+b>, :kill-session```