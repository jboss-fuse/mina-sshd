/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.signature;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;

import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.util.BufferUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.io.der.DERWriter;

/**
 * DSA <code>Signature</code>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSignatureDSA extends AbstractSignature {

    public static final int DSA_SIGNATURE_LENGTH = 40;
    // result must be 40 bytes, but length of r and s may not exceed 20 bytes
    public static final int MAX_SIGNATURE_VALUE_LENGTH = DSA_SIGNATURE_LENGTH / 2;

    protected AbstractSignatureDSA(String algorithm) {
	super(algorithm);
    }

    public byte[] sign() throws Exception {
        byte[] sig = signature.sign();

        // sig is in ASN.1
        // SEQUENCE::={ r INTEGER, s INTEGER }
        int len = 0;
        int index = 3;
        len = sig[index++] & 0xff;
        byte[] r = new byte[len];
        System.arraycopy(sig, index, r, 0, r.length);
        index = index + len + 1;
        len = sig[index++] & 0xff;
        byte[] s = new byte[len];
        System.arraycopy(sig, index, s, 0, s.length);

        byte[] result = new byte[40];

        // result must be 40 bytes, but length of r and s may not be 20 bytes

        System.arraycopy(r,
                         (r.length > 20) ? 1 : 0,
                         result,
                         (r.length > 20) ? 0 : 20 - r.length,
                         (r.length > 20) ? 20 : r.length);
        System.arraycopy(s,
                         (s.length > 20) ? 1 : 0,
                         result,
                         (s.length > 20) ? 20 : 40 - s.length,
                         (s.length > 20) ? 20 : s.length);

        return result;
    }

    public boolean verify(byte[] sig) throws Exception {
        int sigLen = sig == null ? 0 : sig.length;
        byte[] data = sig;

        if (sigLen != DSA_SIGNATURE_LENGTH) {
            // probably some encoded data
            Pair<String, byte[]> encoding = extractEncodedSignature(sig);
            if (encoding != null) {
                String keyType = encoding.getFirst();
                if (!KeyPairProvider.SSH_DSS.equals(keyType)) {
                    throw new IllegalArgumentException(String.format("Mismatched key type: %s", keyType));
                }
                data = encoding.getSecond();
                sigLen = data == null ? 0 : data.length;
            }
        }

        if (sigLen != DSA_SIGNATURE_LENGTH) {
            throw new SignatureException("Bad signature length (" + sigLen + " instead of " + DSA_SIGNATURE_LENGTH + ")"
                    + " for " + BufferUtils.toHex(':', data));
        }

        byte[] rEncoding;
        try (DERWriter w = new DERWriter(MAX_SIGNATURE_VALUE_LENGTH + 4)) {     // in case length > 0x7F
            w.writeBigInteger(data, 0, MAX_SIGNATURE_VALUE_LENGTH);
            rEncoding = w.toByteArray();
        }

        byte[] sEncoding;
        try (DERWriter w = new DERWriter(MAX_SIGNATURE_VALUE_LENGTH + 4)) {     // in case length > 0x7F
            w.writeBigInteger(data, MAX_SIGNATURE_VALUE_LENGTH, MAX_SIGNATURE_VALUE_LENGTH);
            sEncoding = w.toByteArray();
        }

        int length = rEncoding.length + sEncoding.length;
        byte[] encoded;
        try (DERWriter w = new DERWriter(1 + length + 4)) {  // in case length > 0x7F
            w.write(0x30); // SEQUENCE
            w.writeLength(length);
            w.write(rEncoding);
            w.write(sEncoding);
            encoded = w.toByteArray();
        }

        return signature.verify(encoded);
    }

    private static final int BYTES = (Integer.SIZE / Byte.SIZE);

    /**
     * Makes an attempt to detect if the signature is encoded or pure data
     *
     * @param sig The original signature
     * @return A {@link Pair} where first value is the key type and second
     * value is the data - {@code null} if not encoded
     */
    protected Pair<String, byte[]> extractEncodedSignature(byte[] sig) {
        final int dataLen = sig == null ? 0 : sig.length;

        // if it is encoded then we must have at least 2 UINT32 values
        if (dataLen < (2 * BYTES)) {
            return null;
        }

        long keyTypeLen = BufferUtils.getUInt(sig, 0, dataLen);
        // after the key type we MUST have data bytes
        if (keyTypeLen >= (dataLen - BYTES)) {
            return null;
        }

        int keyTypeStartPos = BYTES;
        int keyTypeEndPos = keyTypeStartPos + (int) keyTypeLen;
        int remainLen = dataLen - keyTypeEndPos;
        // must have UINT32 with the data bytes length
        if (remainLen < BYTES) {
            return null;
        }

        long dataBytesLen = BufferUtils.getUInt(sig, keyTypeEndPos, remainLen);
        // make sure reported number of bytes does not exceed available
        if (dataBytesLen > (remainLen - BYTES)) {
            return null;
        }

        String keyType = new String(sig, keyTypeStartPos, (int) keyTypeLen, StandardCharsets.UTF_8);
        byte[] data = new byte[(int) dataBytesLen];
        System.arraycopy(sig, keyTypeEndPos + BYTES, data, 0, (int) dataBytesLen);
        return new Pair<>(keyType, data);
    }

}
