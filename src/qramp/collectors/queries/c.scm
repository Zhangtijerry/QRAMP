; QRAMP C / C++ crypto call-site queries (versioned detection rules).
; C crypto idioms differ from scoped-call languages: the algorithm is encoded
; in the FUNCTION NAME (EVP_md5, EVP_aes_256_gcm), or passed as a string
; (EVP_get_cipherbyname("des-cbc")) or an integer (RSA_generate_key(2048,...)).

; --- plain function call: fn(args) — covers EVP_*, RSA_*, DH_*, MD5, SHA1,
;     libsodium crypto_* ---
; @fn = function identifier, @args = argument list
(call_expression
  function: (identifier) @fn
  arguments: (argument_list) @args) @site
