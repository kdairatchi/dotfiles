#!/bin/bash
echo "Linking all tools in ~/tools to /usr/local/bin"

for tool in ~/tools/*; do
  if [[ -x "$tool/$tool" ]]; then
    sudo ln -sf "$tool/$tool" "/usr/local/bin/$(basename $tool)"
    echo "Linked: $(basename $tool)"
  fi
done
