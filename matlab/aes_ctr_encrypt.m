function ciphertext = aes_ctr_encrypt(plaintext, aes_key, nonce)
%AES_CTR_ENCRYPT  AES-256-CTR mode encryption.
%
%   CIPHERTEXT = aes_ctr_encrypt(PLAINTEXT, AES_KEY, NONCE)
%
%   INPUTS:
%       plaintext : uint8 vector (row or column), any length
%       aes_key   : 1x32 uint8  (256-bit key)
%       nonce     : 1x16 uint8  (128-bit initial counter block)
%
%   OUTPUT:
%       ciphertext : uint8 row vector, same length as plaintext
%
%   PROPERTIES:
%       Output length == Input length (CTR is a stream cipher, no padding).
%       Self-inverse: aes_ctr_encrypt(aes_ctr_encrypt(x,k,n),k,n) == x.
%       Counter format: 128-bit big-endian (NIST SP 800-38A compatible).
%       Uses Java javax.crypto.Cipher 'AES/CTR/NoPadding'.
%
%   Reference: javax.crypto.Cipher -- Java SE 8 API
%              NIST SP 800-38A (CTR mode specification)
%              MathWorks -- Call Java from MATLAB (R2021a)

    import javax.crypto.spec.SecretKeySpec
    import javax.crypto.spec.IvParameterSpec
    import javax.crypto.Cipher

    % --- Input validation ---
    if ~isa(plaintext, 'uint8') || ~isvector(plaintext) || isempty(plaintext)
        error('aes_ctr_encrypt:badInput', ...
              'plaintext must be a non-empty uint8 vector.');
    end
    if ~isa(aes_key, 'uint8') || numel(aes_key) ~= 32
        error('aes_ctr_encrypt:badKey', ...
              'aes_key must be a 1x32 uint8 vector (256-bit).');
    end
    if ~isa(nonce, 'uint8') || numel(nonce) ~= 16
        error('aes_ctr_encrypt:badNonce', ...
              'nonce must be a 1x16 uint8 vector (128-bit).');
    end

    % typecast reinterprets bits without value conversion:
    %   uint8(200) -> int8(-56), same 8 bits, required for Java byte[].
    key_j = typecast(aes_key(:),   'int8');
    iv_j  = typecast(nonce(:),     'int8');
    pt_j  = typecast(plaintext(:), 'int8');

    key_spec = SecretKeySpec(key_j, 'AES');
    iv_spec  = IvParameterSpec(iv_j);
    c = Cipher.getInstance('AES/CTR/NoPadding');
    c.init(Cipher.ENCRYPT_MODE, key_spec, iv_spec);

    ct_j = c.doFinal(pt_j);
    ciphertext = typecast(ct_j, 'uint8')';   % uint8 row vector

    assert(numel(ciphertext) == numel(plaintext), ...
           'aes_ctr_encrypt: output length mismatch (internal error).');
end
