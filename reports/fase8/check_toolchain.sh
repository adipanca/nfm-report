#!/bin/bash
for c in gcc g++ cmake make parallel dot wget; do
  if command -v "$c" >/dev/null 2>&1; then
    v=$("$c" --version 2>&1 | head -1)
    echo "$c: $v"
  else
    echo "$c: MISSING"
  fi
done
