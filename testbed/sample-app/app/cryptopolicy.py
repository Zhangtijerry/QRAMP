

def make_dh_params():
    from cryptography.hazmat.primitives.asymmetric import dh
    # weak: 1024-bit finite-field DH parameters
    return dh.generate_parameters(generator=2, key_size=1024)
