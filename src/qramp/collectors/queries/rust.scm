; QRAMP Rust crypto call-site queries (versioned detection rules).

; --- Type::method(...) scoped call, e.g. Md5::new(), RsaPrivateKey::new(...) ---
; @path = the full scoped path (Type::method or mod::Type::method)
; @args = the argument list (for key sizes)
(call_expression
  function: (scoped_identifier) @path
  arguments: (arguments) @args) @site

; --- use paths: `use sha1::Sha1;` etc. (weak signal, lower confidence) ---
; captured so a bare `use md5::Md5;` without a call is still surfaced.
(use_declaration
  argument: (scoped_identifier
              path: (identifier) @crate
              name: (identifier) @item)) @usesite
