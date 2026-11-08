#!/bin/bash
# Usage: run-openvas.sh <baseline|patched>
# Starts the isolated Apache target (2.4.49 for baseline, current 2.4 for patched),
# proves the scanner can reach it on TCP 80, then runs the OpenVAS scan.
set -u
phase="$1"
lab="/mnt/c/Users/bhara/.codex/.chatgpt-projects/g-p-6905865eeff4819188e4c7de7ce34736/SOC_Portfolio_Lab"
case "$phase" in
  baseline) image="httpd:2.4.49" ;;
  patched)  image="httpd:2.4" ;;
  hardened) image="httpd:2.4" ;;
  *) echo "phase must be baseline, patched or hardened"; exit 2 ;;
esac

current=$(docker inspect soc-target-apache --format '{{.Config.Image}}|{{index .Config.Labels "soclab.phase"}}' 2>/dev/null || true)
if [ "$current" != "$image|$phase" ]; then
  docker rm -f soc-target-apache >/dev/null 2>&1
  if [ "$phase" = "hardened" ]; then
    # Same current image, with HTTP TRACE disabled in the main config
    docker create --name soc-target-apache --network soc-openvas-targets \
      --ip 172.31.250.10 --label soclab.phase=hardened "$image" \
      sh -c "echo 'TraceEnable Off' >> /usr/local/apache2/conf/httpd.conf && exec httpd-foreground" >/dev/null || exit 3
  else
    docker create --name soc-target-apache --network soc-openvas-targets \
      --ip 172.31.250.10 --label soclab.phase="$phase" "$image" >/dev/null || exit 3
  fi
fi
docker start soc-target-apache >/dev/null || exit 3
echo "target image: $image -> $(docker exec soc-target-apache httpd -v | head -1)"

for i in $(seq 1 15); do
  if docker exec soc-openvas-ospd-openvas-1 bash -c 'exec 3<>/dev/tcp/172.31.250.10/80' 2>/dev/null; then
    echo "scanner can reach 172.31.250.10:80"; break
  fi
  [ "$i" -eq 15 ] && { echo "target unreachable from scanner"; exit 4; }
  sleep 2
done

cd "$lab" || exit 2
for i in $(seq 1 10); do
  if python3 -I scripts/openvas-scan.py "$phase" "evidence/openvas-$phase.json"; then
    docker ps --filter name=soc-target-apache --format 'target after scan: {{.Status}}'
    exit 0
  fi
  echo "attempt $i failed, retrying in 60s"; sleep 60
done
exit 1
