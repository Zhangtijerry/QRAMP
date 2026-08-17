; QRAMP Go crypto call-site queries (versioned detection rules).

; --- package.Function(...) call, e.g. md5.Sum(...), rsa.GenerateKey(...) ---
; @pkg = package identifier, @fn = function name, @args = argument list
(call_expression
  function: (selector_expression
              operand: (identifier) @pkg
              field: (field_identifier) @fn)
  arguments: (argument_list) @args) @site

; --- tls.<CONST> selector, e.g. tls.VersionTLS10, tls.TLS_RSA_WITH_3DES... ---
; @tlspkg must be "tls"; @const is the constant name.
(selector_expression
  operand: (identifier) @tlspkg (#eq? @tlspkg "tls")
  field: (field_identifier) @const) @tlssite
