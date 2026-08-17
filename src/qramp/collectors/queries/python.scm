; QRAMP Python crypto call-site queries (versioned detection rules).

; --- attribute call: X.method(...)  e.g. hashlib.md5(...), rsa.generate_private_key(...) ---
; @obj = receiver object, @attr = method name, @args = argument list
(call
  function: (attribute
              object: (_) @obj
              attribute: (identifier) @attr)
  arguments: (argument_list) @args) @site

; --- bare-name call: New(...) forms rarely used; kept for AES.new etc. handled via @obj ---

; --- attribute reference (no call): ssl.PROTOCOL_TLSv1 constants ---
(attribute
  object: (identifier) @cobj
  attribute: (identifier) @cattr) @attrsite
