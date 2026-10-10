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
# A hook that fails is non-blocking to Claude Code, so a valvur that cannot start (uvx
# not yet resolving a fresh release, no network for a first fetch) would let the install
# through unasked. The check is never silently off (D44): it asks, naming why.
err=$(mktemp 2>/dev/null) || err=/dev/null
if out=$(printf '%s' "$event" | ${VALVUR_HOOK:-uvx --from valvur==1.5.2 valvur-hook} 2>"$err"); then
  printf '%s' "$out"
else
  why=$(head -c 300 "$err" 2>/dev/null | tr '\n\r\t"\\' "     ")
  printf '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "valvur could not check this install: its check did not start (%s). Install only if you are sure of every package name."}}\n' "$why"
fi
[ "$err" = /dev/null ] || rm -f "$err"
