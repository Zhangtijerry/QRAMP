; QRAMP Java crypto call-site queries (versioned detection rules).
; Each pattern captures a @site anchor plus the fields the interpreter needs.

; --- X.getInstance("spec") on a JCA/JSSE factory class ---
; @recv = factory class (MessageDigest, Cipher, KeyPairGenerator, ...)
; @spec = the algorithm / transformation string literal
(method_invocation
  object: (identifier) @recv
  name: (identifier) @m (#eq? @m "getInstance")
  arguments: (argument_list
               . (string_literal (string_fragment) @spec))) @site

; --- key size via .init(N) / .initialize(N) in the same method body ---
; captured separately; the interpreter associates it with the getInstance
; call in the enclosing method.
(method_invocation
  name: (identifier) @initm (#match? @initm "^(init|initialize)$")
  arguments: (argument_list
               . (decimal_integer_literal) @keysize)) @initsite
