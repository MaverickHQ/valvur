#!/bin/sh
# valvur's check_package hook (R18, D44). Claude Code runs this before every Bash call
# with the call as JSON on stdin. When the command installs a package valvur would
# flag, valvur-hook answers `ask` with each verdict and the human decides; otherwise
# nothing is printed and the usual permission flow applies. It never blocks.
#
# Starting valvur costs about 0.45 s warm (R18.1), so it starts only when the command
# names an installer. VALVUR_HOOK runs another valvur-hook instead, such as a checkout's.
event=$(cat)
case "$event" in
  *npm*|*pnpm*|*yarn*|*bun*|*pip*|*"uv add"*|*poetry*|*cargo*|*gem*|*composer*) ;;
  *) exit 0 ;;
esac
printf '%s' "$event" | ${VALVUR_HOOK:-uvx --from valvur==1.2.0 valvur-hook}
