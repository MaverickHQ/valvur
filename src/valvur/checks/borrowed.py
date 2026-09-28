"""Injection patterns borrowed from Cisco's mcp-scanner (D14, R5.6).

Translated from the YARA rules of cisco-ai-defense/mcp-scanner, Apache-2.0, at commit
9e47aabdf2017b82e78f3419f39a75f20b6f98fa: `mcpscanner/data/yara_rules/`
`prompt_injection.yara`, `coercive_injection.yara`, `data_exfiltration.yara` and
`credential_harvesting.yara`. Credited in `NOTICE`. Each regular expression is the
rule's own string, with YARA's escaped `/` unescaped and its `/i` as IGNORECASE.

Adopted by D14's rule, measured by `scripts/spikes/r5_6_patterns.py`: a string Cisco's
condition treats as a detection on its own (not a modifier, not a part of a
conjunction) that adds no finding on the corpus's agent files, the 263 real
instruction texts in awesome-cursorrules, or valvur's own agent files. Left out for
a hit there: `tool_injection_commands`, `hidden_behavior`, `conversation_exfil`,
`sends_conversation` and `leak_param`; and `upload_external` with
`external_endpoints`, whose precision rests on a negation of template text.
"""

# ruff: noqa: E501 — each pattern is Cisco's string verbatim, so it can be read
# against the source; wrapping it would make that comparison harder.

from __future__ import annotations

import re

#: (valvur rule, Cisco's rule and string name, regular expression, ignore case)
PATTERNS: tuple[tuple[str, str, str, bool], ...] = (
    ("prompt-injection", "prompt_injection.instruction_overrides",
     r'\b(Bypass|Dis\W?regard|Do not (follow|Obey)|Forget|Ignore)\s+((all|any|each|every|most|some)\s+(of\s+)?)?((your|the)\s)?(command|communication|conte[nx]t|conversation|data|guidelines|input|instruction|message|request|response|text)(s)?', True),
    ("prompt-injection", "prompt_injection.shadow_parameters",
     r'\b(internalOnly|hiddenParam|shadowTool|bypassChecks|sandboxEscape)\b', True),
    ("prompt-injection", "prompt_injection.advanced_overrides",
     r'\b(disregard\s+(all\s+)?safety\s+guidelines|forget\s+(everything|all)\s+(before|above)|system\s*prompt\s*override)\b', True),
    ("prompt-injection", "prompt_injection.role_redefinition",
     r'\bnew\s+(instructions|directive|guidelines)s?\s*:\s*you\s+are\b', True),
    ("prompt-injection", "prompt_injection.privilege_escalation",
     r'\b(grant\s+(me\s+)?admin\s+(access|privileges?)|bypass\s+(all\s+)?security\s+checks?|elevated\s+permissions?\s+required|sudo\s+mode\s+enabled?|developer\s+mode\s+activated?)\b', True),
    ("prompt-injection", "prompt_injection.html_comment_evasion_system",
     r'<!--[^>]*SYSTEM\s+(INSTRUCTION|OVERRIDE)', True),
    ("prompt-injection", "prompt_injection.html_comment_evasion_admin",
     r'<!--[^>]*ADMIN\s+OVERRIDE', True),
    ("prompt-injection", "prompt_injection.html_comment_evasion_ignore",
     r'<!--[^>]*ignore\s+(all\s+)?(previous\s+)?(safety\s+)?guidelines', True),
    ("prompt-injection", "prompt_injection.html_comment_evasion_exec",
     r'<!--[^>]*(execute[:\s]|curl\s|wget\s|nc\s|bash\s)', True),
    ("prompt-injection", "prompt_injection.markdown_evasion",
     r'```[^`]*(SYSTEM|ADMIN)\s+(OVERRIDE|INSTRUCTION)', True),
    ("prompt-injection", "prompt_injection.bracket_markers",
     r'(\[\[\[|\|\|\|)(SYSTEM|ADMIN|HIDDEN|INTERNAL)[\s_]?(OVERRIDE|INSTRUCTION|COMMAND)(\]\]\]|\|\|\|)', True),
    ("prompt-injection", "prompt_injection.base64_obfuscation",
     r'\b(atob|btoa|base64[_\-]?decode)\s*\(', True),
    ("prompt-injection", "prompt_injection.hidden_markers",
     r'\[(HIDDEN|INTERNAL|SECRET|PRIVATE)\s+(INSTRUCTION|DIRECTIVE|COMMAND)\]', True),
    ("coercive-directive", "coercive_injection.mandatory_execution",
     r'(Always\s+(consult|use|run|execute|invoke|call|trigger|employ)\s+this\s+(tool|function|command|operation)\s+(immediately|first|before|prior|initially))', True),
    ("coercive-directive", "coercive_injection.priority_overrides",
     r'(Before\s+(executing|invoking|running|using|accessing|calling|employing)\s+any\s+other\s+(tool|action|function|command|operation)s?|(You|User)\s+(must|need to|have to|should|are required to)\s+(use|execute|run|invoke|call)\s+this\s+(tool|function|command|operation))', True),
    ("coercive-directive", "coercive_injection.required_precedence",
     r'(Required|Mandatory|Essential)\s+to\s+(execute|use|run|invoke|call)\s+(this|the current)\s+(tool|function|command|operation)\s+(first|before|initially|prior)', True),
    ("coercive-directive", "coercive_injection.hidden_param",
     r'\b(hidden|secret)[_\s](parameter|argument|input)\b', True),
    ("coercive-directive", "coercive_injection.file_access_coercion",
     r'\b((read|parse|cat|dump) (and pass )?(the )?contents? of [^\n\.]*\.(key|pem|ssh|aws)|pass (the )?contents?[^\n]*authentication)\b', True),
    ("coercive-directive", "coercive_injection.model_data_coercion",
     r'\b(add (the )?entire (conversation|system|chain|tools)[^\n]*(to|for|in)[^\n]*(tool|authentication|parameter|worksheet))\b', True),
    ("coercive-directive", "coercive_injection.model_internals",
     r'\b(conversation_history|chain_of_thought|system_prompt|tools_list|model_name)\s*[:=]\s*(add|pass|send|provide)\b', True),
    ("coercive-directive", "coercive_injection.html_tag_with_commands",
     r'\b<(IMPORTANT|critical|urgent)>[^\n]*(read [^\n]*contents?|pass [^\n]*contents?|add [^\n]*entire|send [^\n]*to[^\n]*@|execute[^\n]*before|call[^\n]*first|use[^\n]*authentication)[^\n]*</(IMPORTANT|critical|urgent)>\b', True),
    ("coercive-directive", "coercive_injection.execution_overrides",
     r'\b(do not execute[^\n]*other[^\n]*tool|must[^\n]*this tool|only[^\n]*this tool|tool[^\n]*will not work)\b', True),
    ("coercive-directive", "coercive_injection.behavior_control",
     r'\b(tell (the )?user only|hide (the )?user)\b', True),
    ("coercive-directive", "coercive_injection.tool_poisoning",
     r'\b(sidenote\W+(required|otherwise) [^\n]*tool [^\n]*work|tool\s+will\s+not\s+work\s+unless|must\s+first [^\n]*read [^\n]*config|shadow [^\n]*trusted [^\n]*tool)\b', True),
    ("coercive-directive", "coercive_injection.data_exfiltration_coercion",
     r'\b(list\s+all\s+(api\s+)?keys?|show\s+me?\s+(all\s+)?passwords?|concatenate [^\n]*\s+conversation\s+history|include [^\n]*\b(secrets?|passwords?|keys?|credentials?|tokens?|config|sensitive|private|confidential|internal|system\s+prompt|conversation\s+history) [^\n]*in\s+(your\s+)?response|base64\s+encode [^\n]*\s+credentials?)\b', True),
    ("coercive-directive", "coercive_injection.behavioral_triggers",
     r'\b(if [^\n]*trusted [^\n]*then|when [^\n]*admin [^\n]*detected|random\.(random|choice) [^\n]*instructions?)\b', True),
    ("coercive-directive", "coercive_injection.pre_execution_attacks",
     r'\b(retrieve [^\n]*description [^\n]*user [^\n]*workstation|all\s+commands\s+must\s+include|before [^\n]*using [^\n]*tool [^\n]*read|permission [^\n]*manipulation)\b', True),
    ("coercive-directive", "coercive_injection.conversation_theft",
     r'\b(send [^\n]*conversation\s+history|when [^\n]*detected [^\n]*send [^\n]*full [^\n]*history|highest\s+priority [^\n]*over [^\n]*other [^\n]*tools)\b', True),
    ("coercive-directive", "coercive_injection.code_manipulation",
     r'\b(duplicate [^\n]*code [^\n]*snippets [^\n]*silently|insert [^\n]*vulnerability [^\n]*generated [^\n]*code)\b', True),
    ("exfiltration-directive", "data_exfiltration.suspicious_domains",
     r'\b(attacker|evil|malware|collect|exfil|steal|hack|malicious|c2|command-?and-?control)\.(com|net|org|io|xyz)\b', True),
    ("exfiltration-directive", "data_exfiltration.remote_collection",
     r'\b(collect|gather|aggregate|compile|harvest)(s|ing|ed)?\s+(and\s+)?(send|upload|transmit|forward|sync|store)', True),
    ("exfiltration-directive", "data_exfiltration.hidden_transfer",
     r'\b(invisibly|silently|covertly|secretly|without\s+(user\s+)?knowledge|behind\s+the\s+scenes|in\s+the\s+background)\s+(send|upload|transmit|transfer|sync|store|collect)', True),
    ("exfiltration-directive", "data_exfiltration.hide_from_user",
     r"\b(never|don't|do\s+not)\s+(tell|inform|mention|notify|alert)\s+(the\s+)?(user|them)\b", True),
    ("exfiltration-directive", "data_exfiltration.clipboard_exfil",
     r'\b(clipboard|pasteboard)\s+(content|data|text|history)?\s*(monitor|watch|track|capture|copy|send|upload|stream)', True),
    ("exfiltration-directive", "data_exfiltration.external_logging",
     r'\b(external|remote)\s+(logging|analytics|telemetry)\s+(endpoint|server|service)', True),
    ("exfiltration-directive", "data_exfiltration.screen_exfil",
     r'\b(screen|screenshot|display|capture|recording)\s*(send|upload|transmit|stream|forward)', True),
    ("exfiltration-directive", "data_exfiltration.keylog_patterns",
     r'\b(keylog|keystroke|key\s+press|typing|input)\s*(capture|record|log|monitor|track|send|upload)', True),
    ("exfiltration-directive", "data_exfiltration.file_exfil",
     r'\b(all\s+files?|every\s+file|file\s+contents?|directory\s+contents?)\s+(matching|in|from)?\s*(upload|send|transmit|copy|sync|backup)\s+(to\s+)?(external|remote|server|cloud|https?://|wss?://)', True),
    ("credential-harvesting", "credential_harvesting.base64_credential_encoding",
     r'\b(base64\s+encode [^\n]*credentials?|concatenate [^\n]*conversation\s+history)\b', True),
    ("credential-harvesting", "credential_harvesting.mcp_credential_patterns",
     r'\b(claude_desktop_config\.json|~/\.cursor/logs/conversations|plaintext[^\n]*api[^\n]*key|-rw-r--r--[^\n]*password)\b', True),
    ("credential-harvesting", "credential_harvesting.whatsapp_exploit",
     r'\b(_get_all_messages[^\n]*messages\.db|forward[^\n]*message[^\n]*proxy[^\n]*number|whatsapp[^\n]*message[^\n]*history|contact[^\n]*list[^\n]*exfiltrat|reprogram[^\n]*agent[^\n]*interaction)\b', True),
)

#: Cisco's data_exfiltration condition: none of its patterns counts in a file that
#: also matches one of these.
EXFILTRATION_UNLESS: tuple[tuple[str, bool], ...] = (
    (r'(get_env|set_env|read_config|write_config|config_file|settings_file|env_file)', False),
    (r'\b(backup\s+(tool|service|utility)|legitimate\s+(backup|sync)|authorized\s+(upload|sync)|official\s+(cloud|storage))\b', True),
)

COMPILED = tuple((rule, name, re.compile(rx, re.IGNORECASE if i else 0))
                 for rule, name, rx, i in PATTERNS)
EXFILTRATION_EXEMPT = tuple(re.compile(rx, re.IGNORECASE if i else 0)
                            for rx, i in EXFILTRATION_UNLESS)
