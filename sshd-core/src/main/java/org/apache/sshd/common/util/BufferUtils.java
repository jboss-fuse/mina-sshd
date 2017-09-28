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
package org.apache.sshd.common.util;

import java.io.IOException;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BufferUtils {

    public static final char EMPTY_HEX_SEPARATOR = '\0';
    public static final String HEX_DIGITS = "0123456789abcdef";

    public static String printHex(byte[] array) {
        return printHex(array, 0, array.length);
    }

    public static String printHex(byte[] array, int offset, int len) {
        return printHex(array, offset, len, ' ');
    }

    public static String printHex(byte[] array, int offset, int len, char sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            byte b = array[offset + i];
            if (sb.length() > 0) {
                sb.append(sep);
            }
            sb.append(digits[(b >> 4) & 0x0F]);
            sb.append(digits[b & 0x0F]);
        }
        return sb.toString();
    }

    public static boolean equals(byte[] a1, byte[] a2) {
        if (a1.length != a2.length) {
            return false;
        }
        return equals(a1, 0, a2, 0, a1.length);
    }

    public static boolean equals(byte[] a1, int a1Offset, byte[] a2, int a2Offset, int length) {
        if (a1.length < a1Offset + length || a2.length < a2Offset + length) {
            return false;
        }
        while (length-- > 0) {
            if (a1[a1Offset++] != a2[a2Offset++]) {
                return false;
            }
        }
        return true;
    }

    final static char[] digits = {
	    '0' , '1' , '2' , '3' , '4' , '5' ,
	    '6' , '7' , '8' , '9' , 'a' , 'b' ,
	    'c' , 'd' , 'e' , 'f'
    };

    /**
     * @param buf A buffer holding a 32-bit unsigned integer in <B>big endian</B>
     *            format. <B>Note:</B> if more than 4 bytes are available, then only the
     *            <U>first</U> 4 bytes in the buffer will be used
     * @return The result as a {@code long} whose 32 high-order bits are zero
     * @see #getUInt(byte[], int, int)
     */
    public static long getUInt(byte... buf) {
        return getUInt(buf, 0, buf == null ? 0 : buf.length);
    }

    /**
     * @param buf A buffer holding a 32-bit unsigned integer in <B>big endian</B>
     *            format.
     * @param off The offset of the data in the buffer
     * @param len The available data length. <B>Note:</B> if more than 4 bytes
     *            are available, then only the <U>first</U> 4 bytes in the buffer will be
     *            used (starting at the specified <tt>offset</tt>)
     * @return The result as a {@code long} whose 32 high-order bits are zero
     */
    public static long getUInt(byte[] buf, int off, int len) {
        if (len < Integer.SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
        }

        long l = (buf[off] << 24) & 0xff000000L;
        l |= (buf[off + 1] << 16) & 0x00ff0000L;
        l |= (buf[off + 2] << 8) & 0x0000ff00L;
        l |= (buf[off + 3]) & 0x000000ffL;
        return l;
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param value The 32-bit value
     * @param buf   The buffer
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     * @see #putUInt(long, byte[], int, int)
     */
    public static int putUInt(long value, byte[] buf) {
        return putUInt(value, buf, 0, buf == null ? 0 : buf.length);
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param value The 32-bit value
     * @param buf   The buffer
     * @param off   The offset to write the value
     * @param len   The available space
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     */
    public static int putUInt(long value, byte[] buf, int off, int len) {
        if (len < Integer.SIZE / Byte.SIZE) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + (Integer.SIZE / Byte.SIZE) + ", available=" + len);
        }

        buf[off] = (byte) ((value >> 24) & 0xFF);
        buf[off + 1] = (byte) ((value >> 16) & 0xFF);
        buf[off + 2] = (byte) ((value >> 8) & 0xFF);
        buf[off + 3] = (byte) (value & 0xFF);

        return Integer.SIZE / Byte.SIZE;
    }

    public static String toHex(char sep, byte... array) {
        return toHex(array, 0, array == null ? 0 : array.length, sep);
    }

    public static String toHex(byte[] array, int offset, int len, char sep) {
        if (len <= 0) {
            return "";
        }

        try {
            return appendHex(new StringBuilder(len * 3 /* 2 HEX + sep */), array, offset, len, sep).toString();
        } catch (IOException e) {   // unexpected
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static <A extends Appendable> A appendHex(A sb, char sep, byte... array) throws IOException {
        return appendHex(sb, array, 0, array == null ? 0 : array.length, sep);
    }

    public static <A extends Appendable> A appendHex(A sb, byte[] array, int offset, int len, char sep) throws IOException {
        if (len <= 0) {
            return sb;
        }

        for (int curOffset = offset, maxOffset = offset + len; curOffset < maxOffset; curOffset++) {
            byte b = array[curOffset];
            if ((curOffset > offset) && (sep != EMPTY_HEX_SEPARATOR)) {
                sb.append(sep);
            }
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0F));
            sb.append(HEX_DIGITS.charAt(b & 0x0F));
        }

        return sb;
    }

}
