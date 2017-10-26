/************************************************************************* *                                                                       * *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *  *                                                                       * *  This software is free software; you can redistribute it and/or       * *  modify it under the terms of the GNU Lesser General Public           * *  License as published by the Free Software Foundation; either         * *  version 2.1 of the License, or any later version.                    * *                                                                       * *  See terms of license at gnu.org.                                     * *                                                                       * *************************************************************************/package org.ejbca.cvc.util;/** * Utility for mapping between byte values and hex codes *  * @author Keijo Kurkinen, Swedish National Police Board * @version $Id: StringConverter.java 9074 2010-05-20 08:06:39Z anatom $ */public final class StringConverter {    private static final char HEXCHAR[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',	    'F' };    private static final String HEXINDEX = "0123456789abcdef          ABCDEF";    private StringConverter() {    }    public static byte[] hexToByte(final String s) {	final int l = s.length() / 2;	byte data[] = new byte[l];	int j = 0;	for (int i = 0; i < l; i++) {	    char c = s.charAt(j++);	    int n, b;	    n = HEXINDEX.indexOf(c);	    b = (n & 0xf) << 4;	    c = s.charAt(j++);	    n = HEXINDEX.indexOf(c);	    b += (n & 0xf);	    data[i] = (byte) b;	}	return data;    }    public static String byteToHex(final byte b[]) {	return byteToHex(b, null);    }    public static String byteToHex(final byte b[], final String sep) {	final int len = b.length;	final StringBuffer sb = new StringBuffer();	for (int i = 0; i < len; i++) {	    sb.append(byteToHex(b[i]));	    if (sep != null && (i + 1) < len) {		sb.append(sep);	    }	}	return sb.toString();    }    public static String byteToHex(final byte b) {	final int c = ((int) b) & 0xff;	final char c1 = HEXCHAR[c >> 4 & 0xF];	final char c2 = HEXCHAR[c & 0xF];	return Character.toString(c1) + c2;    }}